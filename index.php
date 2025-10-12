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
            case 'delete':
                $this->deleteDomain($_GET['domain'] ?? '');
                break;
            case 'refresh':
                $this->forceRefreshDomain($_GET['domain'] ?? '');
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
        
        $domainData = $this->fetchDomainData($domain, true);
        $domains[$domain] = $domainData;
        $this->saveDomains($domains);
        
        $this->redirectWithMessage('Domain added successfully', 'success');
    }
    
    private function forceRefreshDomain($domain) {
        $domains = $this->loadDomains();
        
        if (!isset($domains[$domain])) {
            $this->redirectWithMessage('Domain not found', 'error');
            return;
        }
        
        // Force fresh data retrieval bypassing cache
        $domainData = $this->fetchDomainData($domain, true);
        $domains[$domain] = $domainData;
        $this->saveDomains($domains);
        
        $this->redirectWithMessage('Domain refreshed (bypassed cache)', 'success', $domain);
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
    
    private function fetchDomainData($domain, $forceFresh = false) {
        $config = $this->loadConfig();
        $data = [];
        
        // Fetch WHOIS data (with optional fresh flag)
        $whoisData = $this->getWhoisData($domain, $forceFresh);
        foreach ($config['whois_fields'] as $field) {
            $data[$field] = $whoisData[$field] ?? 'N/A';
        }
        
        // Fetch DNS data (with optional fresh flag)
        $dnsData = $this->getDnsData($domain, $forceFresh);
        foreach ($config['dns_fields'] as $field) {
            $data[$field] = $dnsData[$field] ?? 'N/A';
        }
        
        $data['last_updated'] = date('Y-m-d H:i:s');
        
        return $data;
    }
    
    private function getWhoisData($domain, $forceFresh = false) {
        $whois = [];
        
        // Get IP address (fresh lookup if forced)
        if ($forceFresh) {
            $ipResult = $this->getFreshIpAddress($domain);
            $whois['ip_address'] = $ipResult['value'];
            $whois['ip_address_fallback'] = $ipResult['fallback'];
        } else {
            // Use PHP's dns_get_record to get all A records as fallback
            $records = dns_get_record($domain, DNS_A);
            if (!empty($records)) {
                $ips = array_column($records, 'ip');
                $whois['ip_address'] = implode(', ', $ips);
            } else {
                $whois['ip_address'] = 'N/A';
            }
            $whois['ip_address_fallback'] = true;
        }
        
        // Get nameservers via DNS (bypass cache if requested)
        if ($forceFresh) {
            $nsResult = $this->getFreshNameservers($domain);
            $whois['nameservers'] = implode(', ', $nsResult['value']);
            $whois['nameservers_fallback'] = $nsResult['fallback'];
        } else {
            $ns = dns_get_record($domain, DNS_NS);
            $nameservers = [];
            if ($ns) {
                foreach ($ns as $record) {
                    $nameservers[] = $record['target'];
                }
            }
            $whois['nameservers'] = implode(', ', $nameservers);
            $whois['nameservers_fallback'] = true;
        }
        
        // Get WHOIS data using socket connection (always fresh)
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
    
    private function getFreshIpAddress($domain) {
        $allIps = [];
        $dnsServers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']; // Google, Cloudflare, OpenDNS
        $hasValidResult = false;
        
        // Get IPv4 addresses (A records) from multiple servers
        foreach ($dnsServers as $server) {
            $ipv4Result = $this->queryExternalDns($domain, 'A', $server);
            if ($ipv4Result !== 'N/A' && $ipv4Result !== 'Not found') {
                $hasValidResult = true;
                $ips = array_map('trim', explode(',', $ipv4Result));
                foreach ($ips as $ip) {
                    if (!empty($ip) && !in_array($ip, $allIps)) {
                        $allIps[] = $ip;
                    }
                }
            }
        }
        
        // Get IPv6 addresses (AAAA records) from multiple servers
        foreach ($dnsServers as $server) {
            $ipv6Result = $this->queryExternalDns($domain, 'AAAA', $server);
            if ($ipv6Result !== 'N/A' && $ipv6Result !== 'Not found') {
                $hasValidResult = true;
                $ips = array_map('trim', explode(',', $ipv6Result));
                foreach ($ips as $ip) {
                    if (!empty($ip) && !in_array($ip, $allIps)) {
                        $allIps[] = $ip;
                    }
                }
            }
        }
        
        // If we got some results, return them
        if ($hasValidResult && !empty($allIps)) {
            return ['value' => implode(', ', $allIps), 'fallback' => false];
        }
        
        // Fallback to PHP built-in functions
        $fallbackIps = [];
        
        // Try IPv4 fallback - get all A records
        $records = dns_get_record($domain, DNS_A);
        if (!empty($records)) {
            $ips = array_column($records, 'ip');
            foreach ($ips as $ip) {
                if (!in_array($ip, $fallbackIps)) {
                    $fallbackIps[] = $ip;
                }
            }
        }
        
        // Try IPv6 fallback - get all AAAA records
        $ipv6Records = dns_get_record($domain, DNS_AAAA);
        if (!empty($ipv6Records)) {
            $ipv6s = array_column($ipv6Records, 'ipv6');
            foreach ($ipv6s as $ipv6) {
                if (!in_array($ipv6, $fallbackIps)) {
                    $fallbackIps[] = $ipv6;
                }
            }
        }
        
        if (!empty($fallbackIps)) {
            return ['value' => implode(', ', $fallbackIps), 'fallback' => true];
        }
        
        return ['value' => 'N/A', 'fallback' => true];
    }
    
    private function getFreshNameservers($domain) {
        $result = $this->queryExternalDns($domain, 'NS', '8.8.8.8');
        
        if ($result !== 'N/A') {
            return ['value' => explode(', ', $result), 'fallback' => false];
        }
        
        return ['value' => [], 'fallback' => true]; // Fallback to empty array
    }
    
    private function queryExternalDns($domain, $recordType, $dnsServer) {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        
        if ($isWindows) {
            // Try multiple nslookup command formats
            $commands = [
                "nslookup -type=$recordType $domain $dnsServer 2>&1",
                "nslookup -q=$recordType $domain $dnsServer 2>&1",
                "nslookup $domain $dnsServer 2>&1"  // fallback without type
            ];
        } else {
            // Try multiple dig command formats
            $commands = [
                "dig @$dnsServer $domain $recordType +short 2>&1",
                "dig @$dnsServer $domain $recordType 2>&1",
                "host -t $recordType $domain $dnsServer 2>&1"  // fallback with host
            ];
        }
        
        foreach ($commands as $command) {
            $output = shell_exec($command);
            
            if ($output && !empty(trim($output))) {
                // Check if output contains error messages
                if (preg_match('/not found|NXDOMAIN|connection timed out|can\'t find/i', $output)) {
                    continue; // Try next command
                }
                
                $result = $this->parseExternalDnsOutput($output, $recordType, $isWindows);
                if ($result !== 'N/A') {
                    return $result;
                }
                
                // If parsing returned N/A, check if this is because no records exist
                // vs because parsing failed on actual data
                if ($recordType === 'AAAA') {
                    // For AAAA, if we get a valid response but no IPv6 addresses, domain has no AAAA
                    if (preg_match('/Non-authoritative answer|Name:|Address:/i', $output) && 
                        !preg_match('/[0-9a-fA-F]*:[0-9a-fA-F:]+/', $output)) {
                        return 'Not found'; // Explicit message that AAAA was checked but not found
                    }
                } elseif ($recordType === 'CNAME') {
                    // For CNAME, if we get SOA data instead of CNAME, subdomain doesn't have CNAME
                    if (preg_match('/primary name server|responsible mail addr|SOA/i', $output) && 
                        !preg_match('/canonical name|is an alias for|CNAME/i', $output)) {
                        return 'Not found';
                    }
                } elseif ($recordType === 'MX') {
                    // For MX, if we get SOA data instead of MX, domain doesn't have MX
                    if (preg_match('/primary name server|responsible mail addr|SOA/i', $output) && 
                        !preg_match('/mail exchanger|MX preference/i', $output)) {
                        return 'Not found';
                    }
                } elseif ($recordType === 'TXT') {
                    // For TXT, if we get SOA data instead of TXT, domain doesn't have TXT
                    if (preg_match('/primary name server|responsible mail addr|SOA/i', $output) && 
                        !preg_match('/"[^"]*"|text =|TXT/i', $output)) {
                        return 'Not found';
                    }
                }
            }
        }
        
        // If all commands failed, return raw output from the first command for debugging
        // But only if it looks like there might be actual data to parse
        if (!empty($commands)) {
            $debugOutput = shell_exec($commands[0]);
            if ($debugOutput && !empty(trim($debugOutput))) {
                // Check if this looks like it contains actual record data
                $hasRecordData = false;
                if ($recordType === 'AAAA') {
                    $hasRecordData = preg_match('/[0-9a-fA-F]*:[0-9a-fA-F:]+/', $debugOutput);
                } elseif ($recordType === 'CNAME') {
                    $hasRecordData = preg_match('/canonical name|is an alias for|CNAME/i', $debugOutput);
                } elseif ($recordType === 'MX') {
                    $hasRecordData = preg_match('/mail exchanger|MX preference/i', $debugOutput);
                } elseif ($recordType === 'TXT') {
                    $hasRecordData = preg_match('/"[^"]*"|text =/i', $debugOutput);
                } elseif ($recordType === 'A') {
                    $hasRecordData = preg_match('/Address:\s*\d+\.\d+\.\d+\.\d+/', $debugOutput);
                } else {
                    // For other record types, check for typical record indicators
                    $hasRecordData = preg_match('/Address:|preference|canonical|text|nameserver/i', $debugOutput);
                }
                
                // If we got SOA data instead of the requested record type, it means "Not found"
                if (preg_match('/primary name server|responsible mail addr|SOA/i', $debugOutput) && !$hasRecordData) {
                    return 'Not found';
                }
                
                if ($hasRecordData) {
                    $lines = explode("\n", trim($debugOutput));
                    $cleanLines = [];
                    foreach ($lines as $line) {
                        $line = trim($line);
                        if (!empty($line)) {
                            $cleanLines[] = $line;
                        }
                    }
                    if (!empty($cleanLines)) {
                        return 'DEBUG: ' . implode(' | ', array_slice($cleanLines, 0, 5));
                    }
                }
            }
        }
        
        return 'N/A';
    }
    
    private function parseExternalDnsOutput($output, $recordType, $isWindows) {
        $results = [];
        $lines = explode("\n", trim($output));
        
        if ($isWindows) {
            // Enhanced nslookup parsing with better pattern matching
            $foundAnswerSection = false;
            $inAnswerSection = false;
            
            foreach ($lines as $line) {
                $line = trim($line);
                
                // Look for the answer section indicators
                if (preg_match('/non-authoritative answer|authoritative answer/i', $line)) {
                    $foundAnswerSection = true;
                    $inAnswerSection = true;
                    continue;
                }
                
                // Look for Name: line which indicates start of answer
                if (preg_match('/^Name:\s*(.+)/i', $line)) {
                    $inAnswerSection = true;
                    continue;
                }
                
                // Skip DNS server information lines when not in answer section
                if (!$inAnswerSection && preg_match('/Server:|Default Server:|Address:/i', $line)) {
                    continue;
                }
                
                // Skip empty lines and comments
                if (empty($line) || preg_match('/^[*;#%]/', $line)) {
                    continue;
                }
                
                switch ($recordType) {
                    case 'A':
                        // Multiple patterns for A records
                        if (preg_match('/Address:\s*(\d+\.\d+\.\d+\.\d+)/', $line, $matches) ||
                            preg_match('/^(\d+\.\d+\.\d+\.\d+)$/', $line, $matches)) {
                            $ip = $matches[1];
                            // Skip DNS server IPs
                            if (!in_array($ip, ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '208.67.222.222', '208.67.220.220'])) {
                                $results[] = $ip;
                            }
                        }
                        break;
                        
                    case 'AAAA':
                        // Enhanced patterns for AAAA records - specifically look for IPv6 format
                        if (preg_match('/Address:\s*([0-9a-fA-F:]+)/', $line, $matches)) {
                            $ipv6 = trim($matches[1]);
                            // More permissive validation: must contain colons and be valid IPv6 format
                            if (strpos($ipv6, ':') !== false && 
                                preg_match('/^[0-9a-fA-F:]+$/', $ipv6) && 
                                !preg_match('/^\d+(\.\d+)*$/', $ipv6)) { // Not IPv4 format
                                $results[] = $ipv6;
                            }
                        } elseif (preg_match('/AAAA IPv6 address = (.+)/', $line, $matches) ||
                                  preg_match('/IPv6 address = (.+)/', $line, $matches)) {
                            $ipv6 = trim($matches[1]);
                            if (strpos($ipv6, ':') !== false && preg_match('/^[0-9a-fA-F:]+$/', $ipv6)) {
                                $results[] = $ipv6;
                            }
                        } elseif (preg_match('/^([0-9a-fA-F:]+)$/', trim($line), $matches)) {
                            // Handle cases where IPv6 address is on its own line
                            $ipv6 = trim($matches[1]);
                            if (strpos($ipv6, ':') !== false && preg_match('/^[0-9a-fA-F:]+$/', $ipv6)) {
                                $results[] = $ipv6;
                            }
                        }
                        break;
                        
                    case 'MX':
                        if (preg_match('/MX preference = (\d+), mail exchanger = (.+)/', $line, $matches) ||
                            preg_match('/mail exchanger = (\d+)\s+(.+)/', $line, $matches) ||
                            preg_match('/(\d+)\s+(.+\.[\w]+)/', $line, $matches)) {
                            if (isset($matches[2])) {
                                $results[] = trim($matches[2]) . ' (' . $matches[1] . ')';
                            }
                        }
                        break;
                        
                    case 'CNAME':
                        if (preg_match('/canonical name = (.+)/', $line, $matches) ||
                            preg_match('/is an alias for (.+)/', $line, $matches) ||
                            preg_match('/CNAME.*?:\s*(.+)/', $line, $matches)) {
                            $results[] = trim($matches[1]);
                        }
                        break;
                        
                    case 'TXT':
                        if (preg_match('/"(.+)"/', $line, $matches) ||
                            preg_match('/text = "(.+)"/', $line, $matches) ||
                            preg_match('/TXT.*?:\s*(.+)/', $line, $matches)) {
                            $results[] = trim($matches[1], '"');
                        }
                        break;
                        
                    case 'NS':
                        if (preg_match('/nameserver = (.+)/', $line, $matches) ||
                            preg_match('/name server (.+)/', $line, $matches) ||
                            preg_match('/NS.*?:\s*(.+)/', $line, $matches)) {
                            $results[] = trim($matches[1]);
                        }
                        break;
                }
            }
        } else {
            // Enhanced dig output parsing
            foreach ($lines as $line) {
                $line = trim($line);
                
                // Skip comments, empty lines, and dig headers
                if (empty($line) || preg_match('/^[;#]/', $line) || 
                    preg_match('/^(\|\||>>|;; )/', $line)) {
                    continue;
                }
                
                // For A records, filter out DNS server IPs
                if ($recordType === 'A') {
                    if (preg_match('/^\d+\.\d+\.\d+\.\d+$/', $line)) {
                        if (!in_array($line, ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '208.67.222.222', '208.67.220.220'])) {
                            $results[] = $line;
                        }
                    }
                } elseif ($recordType === 'AAAA') {
                    // For AAAA records, validate IPv6 format
                    if (preg_match('/^[0-9a-fA-F:]+$/', $line) && strpos($line, ':') !== false) {
                        $results[] = $line;
                    }
                } else {
                    // For other record types, take the line as-is if it looks valid
                    if (strlen($line) > 0 && !preg_match('/^[\d\s]+$/', $line)) {
                        $results[] = $line;
                    }
                }
            }
        }
        
        // If no results were parsed, check if this is a "no records" case vs parsing failure
        if (empty($results)) {
            $outputText = implode(' ', $lines);
            
            // Check for explicit "no records" indicators
            if (preg_match('/No AAAA records|can\'t find.*AAAA|No such type|AAAA record not found/i', $outputText)) {
                return 'Not found';
            }
            
            // Check for other record type specific messages
            switch ($recordType) {
                case 'MX':
                    if (preg_match('/No MX records|can\'t find.*MX/i', $outputText)) {
                        return 'Not found';
                    }
                    break;
                case 'CNAME':
                    if (preg_match('/No CNAME records|can\'t find.*CNAME/i', $outputText)) {
                        return 'Not found';
                    }
                    break;
                case 'TXT':
                    if (preg_match('/No TXT records|can\'t find.*TXT/i', $outputText)) {
                        return 'Not found';
                    }
                    break;
                case 'NS':
                    if (preg_match('/No NS records|can\'t find.*NS/i', $outputText)) {
                        return 'Not found';
                    }
                    break;
            }
            
            // For AAAA records, if we only see basic response without actual IPv6 data, it means no AAAA records
            if ($recordType === 'AAAA') {
                $hasActualData = false;
                foreach ($lines as $line) {
                    // Look for actual IPv6-like data (contains colons and hex)
                    if (preg_match('/[0-9a-fA-F]*:[0-9a-fA-F:]+/', $line)) {
                        $hasActualData = true;
                        break;
                    }
                }
                
                // If no IPv6-like data found, this domain simply doesn't have AAAA records
                if (!$hasActualData) {
                    return 'Not found';
                }
            }
            
            // For CNAME records, check if we got SOA data instead of actual CNAME
            if ($recordType === 'CNAME') {
                $hasActualCname = false;
                $hasSoaData = false;
                
                foreach ($lines as $line) {
                    // Look for actual CNAME data
                    if (preg_match('/canonical name|is an alias for|CNAME/i', $line)) {
                        $hasActualCname = true;
                        break;
                    }
                    // Check if we got SOA (Start of Authority) data instead
                    if (preg_match('/primary name server|responsible mail addr|SOA/i', $line)) {
                        $hasSoaData = true;
                    }
                }
                
                // If we got SOA data but no CNAME, the subdomain doesn't have CNAME records
                if ($hasSoaData && !$hasActualCname) {
                    return 'Not found';
                }
                
                // If no CNAME-like data found at all
                if (!$hasActualCname) {
                    return 'Not found';
                }
            }
            
            // For MX records, check for similar issues
            if ($recordType === 'MX') {
                $hasActualMx = false;
                $hasSoaData = false;
                
                foreach ($lines as $line) {
                    // Look for actual MX data
                    if (preg_match('/mail exchanger|MX preference|priority/i', $line)) {
                        $hasActualMx = true;
                        break;
                    }
                    // Check if we got SOA data instead
                    if (preg_match('/primary name server|responsible mail addr|SOA/i', $line)) {
                        $hasSoaData = true;
                    }
                }
                
                // If we got SOA data but no MX, domain doesn't have MX records
                if ($hasSoaData && !$hasActualMx) {
                    return 'Not found';
                }
                
                if (!$hasActualMx) {
                    return 'Not found';
                }
            }
            
            // For TXT records, similar logic
            if ($recordType === 'TXT') {
                $hasActualTxt = false;
                $hasSoaData = false;
                
                foreach ($lines as $line) {
                    // Look for actual TXT data (quoted strings)
                    if (preg_match('/"[^"]*"|text =|TXT/i', $line)) {
                        $hasActualTxt = true;
                        break;
                    }
                    // Check if we got SOA data instead
                    if (preg_match('/primary name server|responsible mail addr|SOA/i', $line)) {
                        $hasSoaData = true;
                    }
                }
                
                // If we got SOA data but no TXT, domain doesn't have TXT records
                if ($hasSoaData && !$hasActualTxt) {
                    return 'Not found';
                }
                
                if (!$hasActualTxt) {
                    return 'Not found';
                }
            }
            
            // For other record types or when there seems to be data but parsing failed
            // Clean up the output and return first few meaningful lines
            $cleanLines = [];
            foreach ($lines as $line) {
                $line = trim($line);
                if (!empty($line) && 
                    !preg_match('/^[;#%]/', $line) && 
                    !preg_match('/Server:|Default Server|Address.*8\.8\.8\.8|Address.*1\.1\.1\.1|Address.*208\.67\.222\.222/i', $line)) {
                    $cleanLines[] = $line;
                }
            }
            
            if (!empty($cleanLines)) {
                return 'RAW: ' . implode(' | ', array_slice($cleanLines, 0, 3));
            }
        }
        
        return empty($results) ? 'N/A' : implode(', ', $results);
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
    
    private function getDnsData($domain, $forceFresh = false) {
        $dns = [];
        
        if ($forceFresh) {
            // Use external DNS servers to bypass local cache
            return $this->getDnsDataViaExternalServers($domain);
        } else {
            // Original method using PHP's built-in functions
            return $this->getDnsDataBuiltIn($domain);
        }
    }
    
    private function getDnsDataViaExternalServers($domain) {
        $dns = [];
        $dnsServers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']; // Google, Cloudflare, OpenDNS
        
        try {
            // A records - try multiple DNS servers
            $aResult = $this->queryMultipleDnsServers($domain, 'A', $dnsServers);
            $dns['a_records'] = $aResult['value'];
            $dns['a_records_fallback'] = $aResult['fallback'];
            
            // AAAA records
            $aaaaResult = $this->queryMultipleDnsServers($domain, 'AAAA', $dnsServers);
            $dns['aaaa_records'] = $aaaaResult['value'];
            $dns['aaaa_records_fallback'] = $aaaaResult['fallback'];
            
            // MX records
            $mxResult = $this->queryMultipleDnsServers($domain, 'MX', $dnsServers);
            $dns['mx_records'] = $mxResult['value'];
            $dns['mx_records_fallback'] = $mxResult['fallback'];
            
            // CNAME records - check www subdomain if domain doesn't start with www
            $cname_domain = $domain;
            if (!preg_match('/^www\./i', $domain)) {
                $cname_domain = 'www.' . $domain;
            }
            $cnameResult = $this->queryMultipleDnsServers($cname_domain, 'CNAME', $dnsServers);
            $dns['cname_records'] = $cnameResult['value'];
            $dns['cname_records_fallback'] = $cnameResult['fallback'];
            
            // TXT records
            $txtResult = $this->queryMultipleDnsServers($domain, 'TXT', $dnsServers);
            $dns['txt_records'] = $txtResult['value'];
            $dns['txt_records_fallback'] = $txtResult['fallback'];
            
        } catch (Exception $e) {
            // Fallback to built-in functions if external queries fail
            return $this->getDnsDataBuiltIn($domain);
        }
        
        return $dns;
    }
    
    // Query multiple DNS servers until we get a result
    private function queryMultipleDnsServers($domain, $recordType, $dnsServers) {
        $allResults = [];
        $hasValidResult = false;
        
        // Query all DNS servers and collect unique results
        foreach ($dnsServers as $server) {
            $result = $this->queryExternalDns($domain, $recordType, $server);
            if ($result !== 'N/A' && $result !== 'Not found' && !empty($result)) {
                $hasValidResult = true;
                // Split by comma in case one server returns multiple IPs
                $ips = array_map('trim', explode(',', $result));
                foreach ($ips as $ip) {
                    if (!empty($ip) && !in_array($ip, $allResults)) {
                        $allResults[] = $ip;
                    }
                }
            }
        }
        
        // If we got results from external servers, return them
        if ($hasValidResult && !empty($allResults)) {
            return ['value' => implode(', ', $allResults), 'fallback' => false];
        }
        
        // If all external servers failed, fallback to PHP built-in functions
        $fallbackResult = $this->getBuiltInDnsRecord($domain, $recordType);
        return ['value' => $fallbackResult, 'fallback' => true];
    }
    
    // Fallback to PHP built-in DNS functions for a specific record type
    private function getBuiltInDnsRecord($domain, $recordType) {
        try {
            switch ($recordType) {
                case 'A':
                    $records = dns_get_record($domain, DNS_A);
                    return !empty($records) ? implode(', ', array_column($records, 'ip')) : 'Not found';
                    
                case 'AAAA':
                    $records = dns_get_record($domain, DNS_AAAA);
                    return !empty($records) ? implode(', ', array_column($records, 'ipv6')) : 'Not found';
                    
                case 'MX':
                    $records = dns_get_record($domain, DNS_MX);
                    if (!empty($records)) {
                        $mx_list = [];
                        foreach ($records as $record) {
                            $mx_list[] = $record['target'] . ' (' . $record['pri'] . ')';
                        }
                        return implode(', ', $mx_list);
                    }
                    return 'Not found';
                    
                case 'CNAME':
                    $records = dns_get_record($domain, DNS_CNAME);
                    return !empty($records) ? implode(', ', array_column($records, 'target')) : 'Not found';
                    
                case 'TXT':
                    $records = dns_get_record($domain, DNS_TXT);
                    return !empty($records) ? implode(', ', array_column($records, 'txt')) : 'Not found';
                    
                case 'NS':
                    $records = dns_get_record($domain, DNS_NS);
                    return !empty($records) ? implode(', ', array_column($records, 'target')) : 'Not found';
                    
                default:
                    return 'N/A';
            }
        } catch (Exception $e) {
            return 'ERROR: ' . $e->getMessage();
        }
    }
    
    private function getDnsDataBuiltIn($domain) {
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
        
        foreach ($xml->whois->field as $field) {
            $config['whois_fields'][] = (string)$field['name'];
        }
        
        foreach ($xml->dns->field as $field) {
            $config['dns_fields'][] = (string)$field['name'];
        }
        
        foreach ($xml->display->field as $field) {
            $fieldName = (string)$field['name'];
            $defaultValue = (string)$field['default'] === 'true';
            
            // Use XML default directly (no separate preferences file)
            $config['display_fields'][] = [
                'name' => $fieldName,
                'label' => (string)$field['label'],
                'default' => $defaultValue
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
        $configFile = 'config.xml';
        
        if (!file_exists($configFile)) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Config file not found']);
            exit;
        }
        
        $xml = simplexml_load_file($configFile);
        if (!$xml) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Could not load XML']);
            exit;
        }
        
        // Convert array of field names to associative array with boolean values
        $config = $this->loadConfig();
        $preferences = [];
        foreach ($config['display_fields'] as $field) {
            $preferences[$field['name']] = in_array($field['name'], $fields);
        }
        
        // Update the default attributes in the display section
        foreach ($xml->display->field as $field) {
            $fieldName = (string)$field['name'];
            if (isset($preferences[$fieldName])) {
                $field['default'] = $preferences[$fieldName] ? 'true' : 'false';
            }
        }
        
        // Format and save the XML
        $dom = new DOMDocument('1.0', 'UTF-8');
        $dom->formatOutput = true;
        $dom->preserveWhiteSpace = false;
        $dom->loadXML($xml->asXML());
        
        $success = $dom->save($configFile);
        
        header('Content-Type: application/json');
        echo json_encode(['success' => (bool)$success]);
        exit;
    }
    
    private function loadFieldPreferences() {
        // No longer needed - preferences are read directly from config.xml
        return [];
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
            color: #000000ff;
        }
        
        .container {
            width: 100%;
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
            min-width: 80px;
        }
        
        .table th {
            background: #f8f9fa;
            font-weight: 600;
            border-bottom: 1px solid #ddd;
            cursor: pointer;
            user-select: none;
            position: relative;
        }
        
        .table th:hover {
            background: #e9ecef;
        }
        
        .table th.sortable::after {
            content: ' ↕';
            color: #999;
            font-size: 10px;
            margin-left: 4px;
        }
        
        .table th.sort-asc::after {
            content: ' ↑';
            color: #007acc;
        }
        
        .table th.sort-desc::after {
            content: ' ↓';
            color: #007acc;
        }
        
        .table tbody tr:hover {
            background: #f8f9fa;
            cursor: pointer;
        }
        
        .table tbody tr.highlight {
            background: #fff3cd !important;
            border-left: 4px solid #ffc107;
        }
        
        .table tbody tr.highlight .value-divider {
            border-bottom-color: #d4a843 !important;
        }
        
        .fallback-cell {
            background-color: #fff3cd !important;
            border-left: 3px solid #ffc107 !important;
        }
        
        .fallback-indicator {
            color: #856404;
            font-size: 9px;
            font-style: italic;
            display: block;
            margin-top: 2px;
        }
        
        .raw-data {
            background-color: #f8f9fa !important;
            border-left: 3px solid #6c757d !important;
            font-family: 'Courier New', monospace;
            font-size: 10px;
            color: #495057;
        }
        
        .debug-data {
            background-color: #e2e3e5 !important;
            border-left: 3px solid #6c757d !important;
            font-family: 'Courier New', monospace;
            font-size: 10px;
            color: #495057;
        }
        
        .error-data {
            background-color: #f8d7da !important;
            border-left: 3px solid #dc3545 !important;
            font-family: 'Courier New', monospace;
            font-size: 10px;
            color: #721c24;
        }
        
        .no-records {
            background-color: #e7f3ff !important;
            
            font-style: italic;
            color: #004085;
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
        let currentSort = { field: null, direction: 'asc' };
        let highlightedDomain = null;
        
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
                    highlightedDomain = highlight;
                    highlightDomain(highlight);
                }
                
            } catch (error) {
                document.getElementById('loading').innerHTML = 'Error loading data: ' + error.message;
            }
        }
        
        function sortData(fieldName) {
            if (currentSort.field === fieldName) {
                // Toggle direction if same field
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                // New field, start with ascending
                currentSort.field = fieldName;
                currentSort.direction = 'asc';
            }
            
            domainsData.domains.sort((a, b) => {
                let valueA = a[fieldName] || '';
                let valueB = b[fieldName] || '';
                
                // Special handling for time_since_update field
                if (fieldName === 'time_since_update') {
                    valueA = convertTimeToSeconds(valueA);
                    valueB = convertTimeToSeconds(valueB);
                } else {
                    // Convert to strings for comparison
                    valueA = String(valueA).toLowerCase();
                    valueB = String(valueB).toLowerCase();
                    
                    // Handle special cases for dates
                    if (fieldName.includes('date') || fieldName === 'last_updated') {
                        valueA = new Date(valueA).getTime() || 0;
                        valueB = new Date(valueB).getTime() || 0;
                    }
                }
                
                let result = 0;
                if (valueA < valueB) result = -1;
                else if (valueA > valueB) result = 1;
                
                return currentSort.direction === 'asc' ? result : -result;
            });
            
            renderTable();
        }
        
        function convertTimeToSeconds(timeString) {
            if (!timeString || timeString === 'N/A' || timeString === 'Unknown') {
                return 999999; // Put N/A values at the end
            }
            
            // Parse time strings like "5m ago", "2h ago", "3d ago", "30s ago"
            const match = timeString.match(/(\d+)([smhd])\s*ago/i);
            if (!match) {
                return 999999; // Unknown format, put at end
            }
            
            const value = parseInt(match[1]);
            const unit = match[2].toLowerCase();
            
            switch (unit) {
                case 's': return value; // seconds
                case 'm': return value * 60; // minutes to seconds
                case 'h': return value * 3600; // hours to seconds
                case 'd': return value * 86400; // days to seconds
                default: return 999999;
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
            
            // Add visible field headers with click handlers
            domainsData.fields.forEach(field => {
                if (visibleFields.has(field.name)) {
                    const th = document.createElement('th');
                    th.textContent = field.label;
                    th.className = 'sortable';
                    th.setAttribute('data-field', field.name);
                    
                    // Add sort indicator
                    if (currentSort.field === field.name) {
                        th.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
                    }
                    
                    // Add click handler for sorting
                    th.addEventListener('click', () => {
                        sortData(field.name);
                    });
                    
                    header.appendChild(th);
                }
            });
            
            // Add time since update header
            const timeTh = document.createElement('th');
            timeTh.textContent = 'Updated';
            timeTh.className = 'sortable';
            timeTh.setAttribute('data-field', 'time_since_update');
            
            if (currentSort.field === 'time_since_update') {
                timeTh.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
            }
            
            timeTh.addEventListener('click', () => {
                sortData('time_since_update');
            });
            
            header.appendChild(timeTh);
            
            // Add actions header (not sortable)
            const actionsTh = document.createElement('th');
            actionsTh.textContent = 'Actions';
            header.appendChild(actionsTh);
            
            // Add domain rows
            domainsData.domains.forEach(domain => {
                const tr = document.createElement('tr');
                tr.setAttribute('data-domain', domain.domain);
                
                // Apply highlighting if this is the highlighted domain
                if (highlightedDomain === domain.domain) {
                    tr.classList.add('highlight');
                }
                
                // Add visible field data
                domainsData.fields.forEach(field => {
                    if (visibleFields.has(field.name)) {
                        const td = document.createElement('td');
                        let cellValue = domain[field.name] || 'N/A';
                        const fallbackKey = field.name + '_fallback';
                        const isFallback = domain[fallbackKey] === true;
                        
                        // Apply fallback styling if needed
                        if (isFallback) {
                            td.classList.add('fallback-cell');
                        }
                        
                        // Apply special styling for raw/debug/error data
                        if (typeof cellValue === 'string') {
                            if (cellValue.startsWith('RAW: ')) {
                                td.classList.add('raw-data');
                            } else if (cellValue.startsWith('DEBUG: ')) {
                                td.classList.add('debug-data');
                            } else if (cellValue.startsWith('ERROR: ')) {
                                td.classList.add('error-data');
                            } else if (cellValue === 'Not found') {
                                td.classList.add('no-records');
                            }
                        }
                        
                        // Convert comma-separated and semicolon-separated values to new lines
                        if (cellValue && (cellValue.includes(',') || cellValue.includes(';'))) {
                            const values = cellValue.split(/[,;]/).map(item => item.trim());
                            
                            // Create separate div elements for each value with borders
                            td.innerHTML = '';
                            values.forEach((value, index) => {
                                const valueDiv = document.createElement('div');
                                valueDiv.textContent = value;
                                valueDiv.style.padding = '2px 0';
                                valueDiv.className = 'value-divider';
                                valueDiv.style.borderBottom = index < values.length - 1 ? '1px solid #eee' : 'none';
                                td.appendChild(valueDiv);
                            });
                            
                            // Add fallback indicator if needed
                            if (isFallback) {
                                const fallbackDiv = document.createElement('div');
                                fallbackDiv.className = 'fallback-indicator';
                                fallbackDiv.textContent = '(cached)';
                                td.appendChild(fallbackDiv);
                            }
                        } else {
                            td.textContent = cellValue;
                            
                            // Add fallback indicator if needed
                            if (isFallback) {
                                const fallbackSpan = document.createElement('span');
                                fallbackSpan.className = 'fallback-indicator';
                                fallbackSpan.textContent = ' (cached)';
                                td.appendChild(fallbackSpan);
                            }
                        }
                        
                        td.title = cellValue + (isFallback ? ' (from local cache)' : ' (fresh from external DNS)'); // Tooltip for full text
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
                        <a href="?action=refresh&domain=${encodeURIComponent(domain.domain)}" class="btn btn-small" style="background: #28a745; border-color: #28a745;" title="Refresh data bypassing cache">Refresh</a>
                        <a href="?action=delete&domain=${encodeURIComponent(domain.domain)}" class="btn btn-small btn-danger" onclick="return confirm('Delete this domain?')">Delete</a>
                    </div>
                `;
                tr.appendChild(actionsTd);
                
                body.appendChild(tr);
            });
        }
        
        function highlightDomain(domainName) {
            // Remove highlight from any previously highlighted domain
            const previousHighlight = document.querySelector('tr.highlight');
            if (previousHighlight) {
                previousHighlight.classList.remove('highlight');
            }
            
            highlightedDomain = domainName;
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