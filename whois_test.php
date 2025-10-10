<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Test domain - change this to test different domains
$testDomain = 'google.com';

echo "<h2>WHOIS Testing Script</h2>\n";
echo "<p>Testing domain: <strong>$testDomain</strong></p>\n";
echo "<hr>\n";

// Test 1: Check if shell_exec is available
echo "<h3>1. Testing shell_exec availability</h3>\n";
if (function_exists('shell_exec')) {
    echo "✓ shell_exec() function is available<br>\n";
    
    // Test basic command
    $testCmd = shell_exec('echo "test"');
    if ($testCmd) {
        echo "✓ Basic shell commands work<br>\n";
    } else {
        echo "✗ Basic shell commands failed<br>\n";
    }
} else {
    echo "✗ shell_exec() function is disabled<br>\n";
}

echo "<hr>\n";

// Test 2: Try whois command directly
echo "<h3>2. Testing WHOIS command</h3>\n";
$escapedDomain = escapeshellarg($testDomain);

// Test different whois command variations
$whoisCommands = [
    "whois $escapedDomain",
    "whois.exe $escapedDomain",
    "C:\\Windows\\System32\\whois.exe $escapedDomain"
];

$whoisOutput = null;
$workingCommand = null;

foreach ($whoisCommands as $cmd) {
    echo "Trying: <code>$cmd</code><br>\n";
    $output = shell_exec("$cmd 2>&1");
    
    if ($output && strlen(trim($output)) > 50 && !preg_match('/not found|command not found|is not recognized/i', $output)) {
        echo "✓ Command worked!<br>\n";
        $whoisOutput = $output;
        $workingCommand = $cmd;
        break;
    } else {
        echo "✗ Command failed or returned minimal output<br>\n";
        if ($output) {
            echo "Output: " . htmlspecialchars(substr($output, 0, 200)) . "...<br>\n";
        }
    }
}

echo "<hr>\n";

// Test 3: Try nslookup as fallback
echo "<h3>3. Testing nslookup (fallback)</h3>\n";
$nslookupOutput = shell_exec("nslookup $escapedDomain 2>&1");
if ($nslookupOutput) {
    echo "✓ nslookup works<br>\n";
    echo "<pre>" . htmlspecialchars(substr($nslookupOutput, 0, 500)) . "</pre>\n";
} else {
    echo "✗ nslookup failed<br>\n";
}

echo "<hr>\n";

// Test 4: Parse WHOIS output if we got any
if ($whoisOutput) {
    echo "<h3>4. WHOIS Raw Output</h3>\n";
    echo "<details><summary>Click to view raw WHOIS data</summary>\n";
    echo "<pre style='background:#f5f5f5; padding:10px; max-height:400px; overflow:auto;'>";
    echo htmlspecialchars($whoisOutput);
    echo "</pre></details>\n";
    
    echo "<h3>5. Parsed WHOIS Data</h3>\n";
    $parsedData = parseWhoisOutput($whoisOutput);
    
    echo "<table border='1' cellpadding='5' cellspacing='0'>\n";
    foreach ($parsedData as $key => $value) {
        echo "<tr><td><strong>" . ucwords(str_replace('_', ' ', $key)) . "</strong></td><td>" . htmlspecialchars($value) . "</td></tr>\n";
    }
    echo "</table>\n";
} else {
    echo "<h3>4. No WHOIS Data Retrieved</h3>\n";
    echo "<p>❌ Could not retrieve WHOIS data using shell commands</p>\n";
    
    // Test alternative approach using sockets
    echo "<h3>5. Testing Socket-based WHOIS</h3>\n";
    $socketWhois = getWhoisViaSocket($testDomain);
    if ($socketWhois) {
        echo "✓ Socket-based WHOIS worked<br>\n";
        echo "<pre style='background:#f5f5f5; padding:10px; max-height:300px; overflow:auto;'>";
        echo htmlspecialchars(substr($socketWhois, 0, 1000));
        echo "</pre>\n";
        
        $parsedSocket = parseWhoisOutput($socketWhois);
        echo "<table border='1' cellpadding='5' cellspacing='0'>\n";
        foreach ($parsedSocket as $key => $value) {
            echo "<tr><td><strong>" . ucwords(str_replace('_', ' ', $key)) . "</strong></td><td>" . htmlspecialchars($value) . "</td></tr>\n";
        }
        echo "</table>\n";
    } else {
        echo "✗ Socket-based WHOIS also failed<br>\n";
    }
}

echo "<hr>\n";

// Test 6: DNS records for comparison
echo "<h3>6. DNS Records (for comparison)</h3>\n";
$dnsData = getDnsData($testDomain);
echo "<table border='1' cellpadding='5' cellspacing='0'>\n";
foreach ($dnsData as $key => $value) {
    echo "<tr><td><strong>" . ucwords(str_replace('_', ' ', $key)) . "</strong></td><td>" . htmlspecialchars($value) . "</td></tr>\n";
}
echo "</table>\n";

// Functions
function parseWhoisOutput($whoisOutput) {
    $data = [
        'registrar' => 'N/A',
        'creation_date' => 'N/A',
        'expiration_date' => 'N/A',
        'registrant' => 'N/A'
    ];
    
    $lines = explode("\n", $whoisOutput);
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        // Match different registrar patterns
        if (preg_match('/(?:Registrar:|Sponsoring Registrar:|Registrar Name:)\s*(.+)/i', $line, $matches)) {
            $data['registrar'] = trim($matches[1]);
        }
        
        // Match creation date patterns
        if (preg_match('/(?:Creation Date:|Created On:|Domain Create Date:|Created:|\[登録年月日\]|\[Created on\])\s*(.+)/i', $line, $matches)) {
            $data['creation_date'] = trim($matches[1]);
        }
        
        // Match expiration date patterns
        if (preg_match('/(?:Registry Expiry Date:|Expiration Date:|Expires On:|Domain Expiration Date:|Expires:|Expiry Date:|\[有効期限\]|\[Expires on\])\s*(.+)/i', $line, $matches)) {
            $data['expiration_date'] = trim($matches[1]);
        }
        
        // Match registrant patterns
        if (preg_match('/(?:Registrant:|Registrant Name:|Registrant Organization:|\[登録者名\])\s*(.+)/i', $line, $matches)) {
            $registrant = trim($matches[1]);
            if (!empty($registrant) && $registrant !== 'N/A') {
                $data['registrant'] = $registrant;
            }
        }
        
        // Alternative registrant patterns
        if (preg_match('/(?:Organization:|org:)\s*(.+)/i', $line, $matches)) {
            $org = trim($matches[1]);
            if (!empty($org) && $org !== 'N/A' && $data['registrant'] === 'N/A') {
                $data['registrant'] = $org;
            }
        }
    }
    
    return $data;
}

function getWhoisViaSocket($domain) {
    $whoisServers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'info' => 'whois.afilias.net',
        'biz' => 'whois.neulevel.biz',
        'name' => 'whois.nic.name'
    ];
    
    $extension = pathinfo($domain, PATHINFO_EXTENSION);
    if (!isset($whoisServers[$extension])) {
        return false;
    }
    
    $whoisServer = $whoisServers[$extension];
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
    
    return $response;
}

function getDnsData($domain) {
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
        
        // MX records
        $mx_records = dns_get_record($domain, DNS_MX);
        $mx_hosts = [];
        if ($mx_records) {
            foreach ($mx_records as $record) {
                $mx_hosts[] = $record['target'] . ' (' . $record['pri'] . ')';
            }
        }
        $dns['mx_records'] = implode(', ', $mx_hosts);
        
        // NS records
        $ns_records = dns_get_record($domain, DNS_NS);
        $nameservers = [];
        if ($ns_records) {
            foreach ($ns_records as $record) {
                $nameservers[] = $record['target'];
            }
        }
        $dns['nameservers'] = implode(', ', $nameservers);
        
    } catch (Exception $e) {
        $dns['error'] = $e->getMessage();
    }
    
    return $dns;
}

echo "<hr>\n";
echo "<h3>Instructions</h3>\n";
echo "<p>To test different domains, edit the <code>\$testDomain</code> variable at the top of this script.</p>\n";
echo "<p>Current test domain: <strong>$testDomain</strong></p>\n";
?>

<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; margin: 10px 0; }
table td, table th { padding: 8px; border: 1px solid #ddd; }
table th { background: #f5f5f5; }
code { background: #f0f0f0; padding: 2px 4px; border-radius: 3px; }
pre { background: #f5f5f5; padding: 10px; border-radius: 5px; }
details { margin: 10px 0; }
</style>