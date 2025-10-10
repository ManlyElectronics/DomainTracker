<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

class DomainTracker {
    private $domainsFile = 'domains.json';
    private $configFile = 'config.xml';
    
    public function __construct() {
        $this->handleRequest();
    }
    
    private function handleRequest() {
        $action = $_GET['action'] ?? '';
        
        switch ($action) {
            case 'add':
                $this->addDomain($_POST['domain'] ?? '');
                break;
            case 'refresh':
                $this->refreshDomain($_GET['domain'] ?? '');
                break;
            case 'delete':
                $this->deleteDomain($_GET['domain'] ?? '');
                break;
            case 'get_data':
                header('Content-Type: application/json');
                echo json_encode($this->getDomainsData());
                exit;
            case 'save_fields':
                $this->saveFieldPreferences($_POST['fields'] ?? []);
                break;
            default:
                $this->displayInterface();
        }
    }
    
    private function addDomain($domain) {
        $domain = trim(strtolower($domain));
        if (empty($domain)) {
            $this->redirectWithMessage('Please enter a domain name', 'error');
            return;
        }
        
        // Validate domain format
        if (!filter_var('http://' . $domain, FILTER_VALIDATE_URL)) {
            $this->redirectWithMessage('Invalid domain format', 'error');
            return;
        }
        
        $domains = $this->loadDomains();
        
        if (isset($domains[$domain])) {
            $this->redirectWithMessage('Domain already exists', 'warning', $domain);
            return;
        }
        
        $domainData = $this->fetchDomainData($domain);
        $domains[$domain] = $domainData;
        $this->saveDomains($domains);
        
        $this->redirectWithMessage('Domain added successfully', 'success');
    }
    
    private function refreshDomain($domain) {
        $domains = $this->loadDomains();
        
        if (!isset($domains[$domain])) {
            $this->redirectWithMessage('Domain not found', 'error');
            return;
        }
        
        $domainData = $this->fetchDomainData($domain);
        $domains[$domain] = $domainData;
        $this->saveDomains($domains);
        
        $this->redirectWithMessage('Domain refreshed successfully', 'success');
    }
    
    private function deleteDomain($domain) {
        $domains = $this->loadDomains();
        
        if (isset($domains[$domain])) {
            unset($domains[$domain]);
            $this->saveDomains($domains);
            $this->redirectWithMessage('Domain deleted successfully', 'success');
        } else {
            $this->redirectWithMessage('Domain not found', 'error');
        }
    }
    
    private function fetchDomainData($domain) {
        $config = $this->loadConfig();
        $data = [];
        
        // Fetch WHOIS data
        $whoisData = $this->getWhoisData($domain);
        foreach ($config['whois_fields'] as $field) {
            $data[$field] = $whoisData[$field] ?? 'N/A';
        }
        
        // Fetch DNS data
        $dnsData = $this->getDnsData($domain);
        foreach ($config['dns_fields'] as $field) {
            $data[$field] = $dnsData[$field] ?? 'N/A';
        }
        
        $data['last_updated'] = date('Y-m-d H:i:s');
        
        return $data;
    }
    
    private function getWhoisData($domain) {
        $whois = [];
        
        // Get IP address
        $ip = gethostbyname($domain);
        $whois['ip_address'] = ($ip !== $domain) ? $ip : 'N/A';
        
        // Get nameservers via DNS
        $ns = dns_get_record($domain, DNS_NS);
        $nameservers = [];
        if ($ns) {
            foreach ($ns as $record) {
                $nameservers[] = $record['target'];
            }
        }
        $whois['nameservers'] = implode(', ', $nameservers);
        
        // Get WHOIS data using socket connection
        $whoisOutput = $this->getWhoisViaSocket($domain);
        
        if ($whoisOutput && !empty(trim($whoisOutput))) {
            $parsedWhois = $this->parseWhoisOutput($whoisOutput);
            $whois = array_merge($whois, $parsedWhois);
        } else {
            // If socket WHOIS fails, set default values
            $whois['registrar'] = 'N/A (whois unavailable)';
            $whois['creation_date'] = 'N/A';
            $whois['expiration_date'] = 'N/A';
            $whois['registrant'] = 'N/A';
        }
        
        return $whois;
    }
    
    private function getWhoisViaSocket($domain) {
        $whoisServers = [
            'com' => 'whois.verisign-grs.com',
            'net' => 'whois.verisign-grs.com',
            'org' => 'whois.pir.org',
            'info' => 'whois.afilias.net',
            'biz' => 'whois.neulevel.biz',
            'name' => 'whois.nic.name',
            'us' => 'whois.nic.us',
            'uk' => 'whois.nic.uk',
            'ca' => 'whois.cira.ca',
            'au' => 'whois.auda.org.au',
            'de' => 'whois.denic.de',
            'fr' => 'whois.nic.fr',
            'it' => 'whois.nic.it',
            'nl' => 'whois.domain-registry.nl',
            'be' => 'whois.dns.be',
            'eu' => 'whois.eu',
            'me' => 'whois.nic.me',
            'io' => 'whois.nic.io',
            'co' => 'whois.nic.co'
        ];
        
        // Extract TLD from domain
        $domainParts = explode('.', $domain);
        $tld = strtolower(end($domainParts));
        
        // For .co.uk, .org.uk etc., use the last two parts
        if (count($domainParts) > 2 && in_array($domainParts[count($domainParts)-2] . '.' . $tld, ['co.uk', 'org.uk', 'ac.uk'])) {
            $tld = 'uk';
        }
        
        if (!isset($whoisServers[$tld])) {
            return false;
        }
        
        $whoisServer = $whoisServers[$tld];
        $port = 43;
        
        $connection = @fsockopen($whoisServer, $port, $errno, $errstr, 10);
        if (!$connection) {
            return false;
        }
        
        fwrite($connection, $domain . "\r\n");
        $response = '';
        while (!feof($connection)) {
            $response .= fgets($connection, 128);
        }
        fclose($connection);
        
        // Some servers return redirects to other whois servers
        if (preg_match('/Whois Server:\s*(.+)/i', $response, $matches)) {
            $redirectServer = trim($matches[1]);
            $redirectConnection = @fsockopen($redirectServer, $port, $errno, $errstr, 10);
            if ($redirectConnection) {
                fwrite($redirectConnection, $domain . "\r\n");
                $redirectResponse = '';
                while (!feof($redirectConnection)) {
                    $redirectResponse .= fgets($redirectConnection, 128);
                }
                fclose($redirectConnection);
                if (strlen($redirectResponse) > strlen($response)) {
                    $response = $redirectResponse;
                }
            }
        }
        
        return $response;
    }
    
    private function parseWhoisOutput($whoisOutput) {
        $data = [
            'registrar' => 'N/A',
            'creation_date' => 'N/A',
            'expiration_date' => 'N/A'
        ];
        
        $lines = explode("\n", $whoisOutput);
        
        foreach ($lines as $line) {
            $line = trim($line);
            
            // Skip empty lines and comments
            if (empty($line) || strpos($line, '%') === 0 || strpos($line, '#') === 0) {
                continue;
            }
            
            // Match different registrar patterns
            if (preg_match('/(?:Registrar:|Sponsoring Registrar:|Registrar Name:|Registrar IANA ID:|registrar:)\s*(.+)/i', $line, $matches)) {
                $registrar = trim($matches[1]);
                if (!empty($registrar) && !preg_match('/^\d+$/', $registrar)) { // Skip IANA IDs
                    $data['registrar'] = $registrar;
                }
            }
            
            // Match creation date patterns
            if (preg_match('/(?:Creation Date:|Created On:|Domain Create Date:|Created:|created:|Record created on|\[登録年月日\]|\[Created on\]|Registration Time:)\s*(.+)/i', $line, $matches)) {
                $data['creation_date'] = trim($matches[1]);
            }
            
            // Match expiration date patterns
            if (preg_match('/(?:Registry Expiry Date:|Expiration Date:|Expires On:|Domain Expiration Date:|Expires:|Expiry Date:|expires:|\[有効期限\]|\[Expires on\]|Expiration Time:)\s*(.+)/i', $line, $matches)) {
                $data['expiration_date'] = trim($matches[1]);
            }
        }
        
        // Post-processing: Clean up dates
        if ($data['creation_date'] !== 'N/A') {
            $data['creation_date'] = $this->formatDate($data['creation_date']);
        }
        if ($data['expiration_date'] !== 'N/A') {
            $data['expiration_date'] = $this->formatDate($data['expiration_date']);
        }
        
        return $data;
    }
    
    private function formatDate($dateString) {
        // Try to parse and format date consistently
        $dateString = trim($dateString);
        
        // Remove common suffixes
        $dateString = preg_replace('/\s+(UTC|GMT|Z)$/i', '', $dateString);
        
        // Try to parse the date
        $timestamp = strtotime($dateString);
        if ($timestamp !== false) {
            return date('Y-m-d H:i:s', $timestamp);
        }
        
        // If parsing fails, return original
        return $dateString;
    }
    
    private function getDnsData($domain) {
        $dns = [];
        
        try {
            // A records
            $a_records = dns_get_record($domain, DNS_A);
            $a_ips = [];
            if ($a_records) {
                foreach ($a_records as $record) {
                    $a_ips[] = $record['ip'];
                }
            }
            $dns['a_records'] = implode(', ', $a_ips);
            
            // AAAA records
            $aaaa_records = dns_get_record($domain, DNS_AAAA);
            $aaaa_ips = [];
            if ($aaaa_records) {
                foreach ($aaaa_records as $record) {
                    $aaaa_ips[] = $record['ipv6'];
                }
            }
            $dns['aaaa_records'] = implode(', ', $aaaa_ips);
            
            // MX records
            $mx_records = dns_get_record($domain, DNS_MX);
            $mx_hosts = [];
            if ($mx_records) {
                foreach ($mx_records as $record) {
                    $mx_hosts[] = $record['target'] . ' (' . $record['pri'] . ')';
                }
            }
            $dns['mx_records'] = implode(', ', $mx_hosts);
            
            // CNAME records - check www subdomain if domain doesn't start with www
            $cname_domain = $domain;
            if (!preg_match('/^www\./i', $domain)) {
                $cname_domain = 'www.' . $domain;
            }
            
            $cname_records = dns_get_record($cname_domain, DNS_CNAME);
            $cnames = [];
            if ($cname_records) {
                foreach ($cname_records as $record) {
                    $cnames[] = $record['target'];
                }
            }
            $dns['cname_records'] = implode(', ', $cnames);
            
            // TXT records
            $txt_records = dns_get_record($domain, DNS_TXT);
            $txt_values = [];
            if ($txt_records) {
                foreach ($txt_records as $record) {
                    $txt_values[] = substr($record['txt'], 0, 100) . (strlen($record['txt']) > 100 ? '...' : '');
                }
            }
            $dns['txt_records'] = implode('; ', $txt_values);
            
        } catch (Exception $e) {
            $dns['a_records'] = 'Error';
            $dns['aaaa_records'] = 'Error';
            $dns['mx_records'] = 'Error';
            $dns['cname_records'] = 'Error';
            $dns['txt_records'] = 'Error';
        }
        
        return $dns;
    }
    
    private function loadConfig() {
        if (!file_exists($this->configFile)) {
            $this->createDefaultConfig();
        }
        
        $xml = simplexml_load_file($this->configFile);
        $config = [
            'whois_fields' => [],
            'dns_fields' => [],
            'display_fields' => []
        ];
        
        // Load saved field preferences
        $savedPreferences = $this->loadFieldPreferences();
        
        foreach ($xml->whois->field as $field) {
            $config['whois_fields'][] = (string)$field['name'];
        }
        
        foreach ($xml->dns->field as $field) {
            $config['dns_fields'][] = (string)$field['name'];
        }
        
        foreach ($xml->display->field as $field) {
            $fieldName = (string)$field['name'];
            $defaultValue = (string)$field['default'] === 'true';
            
            // Use saved preference if exists, otherwise use XML default
            $isDefault = isset($savedPreferences[$fieldName]) ? $savedPreferences[$fieldName] : $defaultValue;
            
            $config['display_fields'][] = [
                'name' => $fieldName,
                'label' => (string)$field['label'],
                'default' => $isDefault
            ];
        }
        
        return $config;
    }
    
    private function createDefaultConfig() {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>
<config>
    <whois>
        <field name="registrar" />
        <field name="creation_date" />
        <field name="expiration_date" />
        <field name="registrant" />
        <field name="nameservers" />
        <field name="ip_address" />
    </whois>
    <dns>
        <field name="a_records" />
        <field name="aaaa_records" />
        <field name="mx_records" />
        <field name="cname_records" />
        <field name="txt_records" />
    </dns>
    <display>
        <field name="domain" label="Domain" default="true" />
        <field name="ip_address" label="IP Address" default="true" />
        <field name="registrar" label="Registrar" default="true" />
        <field name="creation_date" label="Created" default="false" />
        <field name="expiration_date" label="Expires" default="true" />
        <field name="nameservers" label="Name Servers" default="false" />
        <field name="a_records" label="A Records" default="true" />
        <field name="aaaa_records" label="AAAA Records" default="false" />
        <field name="mx_records" label="MX Records" default="true" />
        <field name="cname_records" label="CNAME Records" default="false" />
        <field name="txt_records" label="TXT Records" default="false" />
        <field name="registrant" label="Registrant" default="false" />
        <field name="last_updated" label="Last Updated" default="true" />
    </display>
</config>';
        
        file_put_contents($this->configFile, $xml);
    }
    
    private function loadDomains() {
        if (!file_exists($this->domainsFile)) {
            return [];
        }
        
        $json = file_get_contents($this->domainsFile);
        return json_decode($json, true) ?: [];
    }
    
    private function saveDomains($domains) {
        file_put_contents($this->domainsFile, json_encode($domains, JSON_PRETTY_PRINT));
    }
    
    private function getDomainsData() {
        $domains = $this->loadDomains();
        $config = $this->loadConfig();
        
        $result = [
            'domains' => [],
            'fields' => $config['display_fields']
        ];
        
        foreach ($domains as $domain => $data) {
            $domainData = ['domain' => $domain] + $data;
            
            // Calculate time since last update
            if (isset($data['last_updated'])) {
                $lastUpdate = strtotime($data['last_updated']);
                $timeDiff = time() - $lastUpdate;
                $domainData['time_since_update'] = $this->formatTimeDifference($timeDiff);
            } else {
                $domainData['time_since_update'] = 'Unknown';
            }
            
            $result['domains'][] = $domainData;
        }
        
        return $result;
    }
    
    private function formatTimeDifference($seconds) {
        if ($seconds < 60) return $seconds . 's ago';
        if ($seconds < 3600) return floor($seconds / 60) . 'm ago';
        if ($seconds < 86400) return floor($seconds / 3600) . 'h ago';
        return floor($seconds / 86400) . 'd ago';
    }
    
    private function saveFieldPreferences($fields) {
        $preferencesFile = 'field_preferences.json';
        $preferences = [];
        
        // Convert array of field names to associative array with boolean values
        $config = $this->loadConfig();
        foreach ($config['display_fields'] as $field) {
            $preferences[$field['name']] = in_array($field['name'], $fields);
        }
        
        file_put_contents($preferencesFile, json_encode($preferences, JSON_PRETTY_PRINT));
        
        header('Content-Type: application/json');
        echo json_encode(['success' => true]);
        exit;
    }
    
    private function loadFieldPreferences() {
        $preferencesFile = 'field_preferences.json';
        if (!file_exists($preferencesFile)) {
            return [];
        }
        
        $json = file_get_contents($preferencesFile);
        return json_decode($json, true) ?: [];
    }
    
    private function redirectWithMessage($message, $type, $highlight = '') {
        $params = ['msg=' . urlencode($message), 'type=' . $type];
        if ($highlight) {
            $params[] = 'highlight=' . urlencode($highlight);
        }
        header('Location: ?' . implode('&', $params));
        exit;
    }
    
    private function displayInterface() {
        $message = $_GET['msg'] ?? '';
        $messageType = $_GET['type'] ?? '';
        $highlight = $_GET['highlight'] ?? '';
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Tracker</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 12px;
            line-height: 1.2;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 10px;
        }
        
        .header {
            background: #fff;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        
        .header h1 {
            font-size: 16px;
            margin-bottom: 8px;
        }
        
        .add-form {
            display: flex;
            gap: 8px;
            align-items: center;
        }
        
        .add-form input[type="text"] {
            padding: 4px 6px;
            border: 1px solid #ccc;
            border-radius: 2px;
            font-size: 12px;
            width: 200px;
        }
        
        .btn {
            padding: 4px 8px;
            border: 1px solid #007acc;
            background: #007acc;
            color: white;
            border-radius: 2px;
            cursor: pointer;
            font-size: 11px;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn:hover {
            background: #005a9e;
        }
        
        .btn-danger {
            background: #d63384;
            border-color: #d63384;
        }
        
        .btn-danger:hover {
            background: #b02a5b;
        }
        
        .btn-small {
            padding: 2px 5px;
            font-size: 10px;
        }
        
        .message {
            padding: 6px 10px;
            margin-bottom: 10px;
            border-radius: 2px;
            font-size: 11px;
        }
        
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .message.warning {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .table-container {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 3px;
            margin-bottom: 10px;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }
        
        .table th,
        .table td {
            padding: 4px 6px;
            text-align: left;
            border-bottom: 1px solid #eee;
            vertical-align: top;
            word-wrap: break-word;
            max-width: 200px;
        }
        
        .table th {
            background: #f8f9fa;
            font-weight: 600;
            border-bottom: 1px solid #ddd;
        }
        
        .table tbody tr:hover {
            background: #f8f9fa;
            cursor: pointer;
        }
        
        .table tbody tr.highlight {
            background: #fff3cd !important;
        }
        
        .actions {
            display: flex;
            gap: 4px;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        
        .field-selector {
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 10px;
        }
        
        .field-selector h3 {
            font-size: 12px;
            margin-bottom: 8px;
        }
        
        .field-checkboxes {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 5px;
        }
        
        .field-checkbox {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        
        .field-checkbox input[type="checkbox"] {
            margin: 0;
        }
        
        .field-checkbox label {
            font-size: 11px;
            cursor: pointer;
        }
        
        .no-data {
            text-align: center;
            padding: 30px;
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Domain Tracker</h1>
            <form method="post" action="?action=add" class="add-form">
                <input type="text" name="domain" placeholder="Enter domain name (e.g., example.com)" required>
                <button type="submit" class="btn">Add Domain</button>
            </form>
        </div>
        
        <?php if ($message): ?>
        <div class="message <?= htmlspecialchars($messageType) ?>">
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>
        
        <div class="table-container">
            <div id="loading" class="loading">Loading domains...</div>
            <table class="table" id="domainsTable" style="display: none;">
                <thead>
                    <tr id="tableHeader"></tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
            <div id="noData" class="no-data" style="display: none;">
                No domains found. Add a domain above to get started.
            </div>
        </div>
        
        <div class="field-selector">
            <h3>Display Fields</h3>
            <div class="field-checkboxes" id="fieldCheckboxes"></div>
        </div>
    </div>
    
    <script>
        let domainsData = null;
        let visibleFields = new Set();
        
        async function loadData() {
            try {
                const response = await fetch('?action=get_data');
                domainsData = await response.json();
                
                // Initialize visible fields from defaults
                domainsData.fields.forEach(field => {
                    if (field.default) {
                        visibleFields.add(field.name);
                    }
                });
                
                renderFieldSelector();
                renderTable();
                
                document.getElementById('loading').style.display = 'none';
                
                if (domainsData.domains.length > 0) {
                    document.getElementById('domainsTable').style.display = 'table';
                } else {
                    document.getElementById('noData').style.display = 'block';
                }
                
                // Highlight domain if specified
                const highlight = '<?= $highlight ?>';
                if (highlight) {
                    highlightDomain(highlight);
                }
                
            } catch (error) {
                document.getElementById('loading').innerHTML = 'Error loading data: ' + error.message;
            }
        }
        
        function renderFieldSelector() {
            const container = document.getElementById('fieldCheckboxes');
            container.innerHTML = '';
            
            domainsData.fields.forEach(field => {
                const div = document.createElement('div');
                div.className = 'field-checkbox';
                
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.id = 'field_' + field.name;
                checkbox.checked = visibleFields.has(field.name);
                checkbox.addEventListener('change', () => {
                    if (checkbox.checked) {
                        visibleFields.add(field.name);
                    } else {
                        visibleFields.delete(field.name);
                    }
                    renderTable();
                    saveFieldPreferences();
                });
                
                const label = document.createElement('label');
                label.htmlFor = 'field_' + field.name;
                label.textContent = field.label;
                
                div.appendChild(checkbox);
                div.appendChild(label);
                container.appendChild(div);
            });
        }
        
        async function saveFieldPreferences() {
            try {
                const formData = new FormData();
                visibleFields.forEach(field => {
                    formData.append('fields[]', field);
                });
                
                await fetch('?action=save_fields', {
                    method: 'POST',
                    body: formData
                });
            } catch (error) {
                console.error('Error saving field preferences:', error);
            }
        }
        
        function renderTable() {
            const header = document.getElementById('tableHeader');
            const body = document.getElementById('tableBody');
            
            header.innerHTML = '';
            body.innerHTML = '';
            
            // Add visible field headers
            domainsData.fields.forEach(field => {
                if (visibleFields.has(field.name)) {
                    const th = document.createElement('th');
                    th.textContent = field.label;
                    header.appendChild(th);
                }
            });
            
            // Add time since update header
            const timeTh = document.createElement('th');
            timeTh.textContent = 'Updated';
            header.appendChild(timeTh);
            
            // Add actions header
            const actionsTh = document.createElement('th');
            actionsTh.textContent = 'Actions';
            header.appendChild(actionsTh);
            
            // Add domain rows
            domainsData.domains.forEach(domain => {
                const tr = document.createElement('tr');
                tr.setAttribute('data-domain', domain.domain);
                
                // Add visible field data
                domainsData.fields.forEach(field => {
                    if (visibleFields.has(field.name)) {
                        const td = document.createElement('td');
                        let cellValue = domain[field.name] || 'N/A';
                        
                        // Convert comma-separated and semicolon-separated values to new lines
                        if (cellValue && (cellValue.includes(',') || cellValue.includes(';'))) {
                            const values = cellValue.split(/[,;]/).map(item => item.trim());
                            
                            // Create separate div elements for each value with borders
                            td.innerHTML = '';
                            values.forEach((value, index) => {
                                const valueDiv = document.createElement('div');
                                valueDiv.textContent = value;
                                valueDiv.style.padding = '2px 0';
                                valueDiv.style.borderBottom = index < values.length - 1 ? '1px solid #eee' : 'none';
                                td.appendChild(valueDiv);
                            });
                        } else {
                            td.textContent = cellValue;
                        }
                        
                        td.title = cellValue; // Tooltip for full text
                        tr.appendChild(td);
                    }
                });
                
                // Add time since update
                const timeTd = document.createElement('td');
                timeTd.textContent = domain.time_since_update || 'N/A';
                tr.appendChild(timeTd);
                
                // Add actions
                const actionsTd = document.createElement('td');
                actionsTd.innerHTML = `
                    <div class="actions">
                        <a href="?action=refresh&domain=${encodeURIComponent(domain.domain)}" class="btn btn-small">Refresh</a>
                        <a href="?action=delete&domain=${encodeURIComponent(domain.domain)}" class="btn btn-small btn-danger" onclick="return confirm('Delete this domain?')">Delete</a>
                    </div>
                `;
                tr.appendChild(actionsTd);
                
                // Add click handler for refresh (except on action buttons)
                tr.addEventListener('click', (e) => {
                    if (!e.target.closest('.actions')) {
                        window.location.href = `?action=refresh&domain=${encodeURIComponent(domain.domain)}`;
                    }
                });
                
                body.appendChild(tr);
            });
        }
        
        function highlightDomain(domainName) {
            setTimeout(() => {
                const row = document.querySelector(`tr[data-domain="${domainName}"]`);
                if (row) {
                    row.classList.add('highlight');
                    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }, 100);
        }
        
        // Load data when page loads
        loadData();
    </script>
</body>
</html>
        <?php
    }
}

new DomainTracker();
?>