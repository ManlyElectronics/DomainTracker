<?php
class TestDns {
    private function parseExternalDnsOutput($output, $recordType, $isWindows) {
        $results = [];
        $lines = explode("\n", trim($output));
        
        if ($isWindows) {
            $foundAnswerSection = false;
            $inAnswerSection = false;
            
            foreach ($lines as $line) {
                $line = trim($line);
                
                if (preg_match('/non-authoritative answer|authoritative answer/i', $line)) {
                    $foundAnswerSection = true;
                    $inAnswerSection = true;
                    continue;
                }
                
                if (preg_match('/^Name:\s*(.+)/i', $line)) {
                    $inAnswerSection = true;
                    continue;
                }
                
                if (!$inAnswerSection && preg_match('/Server:|Default Server:|Address:/i', $line)) {
                    continue;
                }
                
                if (empty($line) || preg_match('/^[*;#%]/', $line)) {
                    continue;
                }
                
                switch ($recordType) {
                    case 'AAAA':
                        if (preg_match('/Address:\s*([0-9a-fA-F:]+)/', $line, $matches)) {
                            $ipv6 = trim($matches[1]);
                            if (strpos($ipv6, ':') !== false && 
                                preg_match('/^[0-9a-fA-F:]+$/', $ipv6) && 
                                !preg_match('/^\d+(\.\d+)*$/', $ipv6)) {
                                $results[] = $ipv6;
                            }
                        }
                        break;
                }
            }
        }
        
        return empty($results) ? 'Not found' : implode(', ', $results);
    }
    
    public function test() {
        $output = 'Non-authoritative answer:
Server:  dns.google
Address:  8.8.8.8

Name:    google.com
Address:  2404:6800:4006:80f::200e';
        
        $result = $this->parseExternalDnsOutput($output, 'AAAA', true);
        echo "Result: " . $result . "\n";
        
        // Test multiple servers to get multiple IPs
        echo "\nTesting multiple DNS servers for multiple IPs:\n";
        
        // Test A records to see format
        $aOutput = 'Non-authoritative answer:
Server:  dns.google
Address:  8.8.8.8

Name:    google.com
Address:  142.250.66.206';
        
        $aResult = $this->parseExternalDnsOutput($aOutput, 'A', true);
        echo "A Record Result: " . $aResult . "\n";
    }
}

$test = new TestDns();
$test->test();
?>