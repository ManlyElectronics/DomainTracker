<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set the action to get_data
$_GET['action'] = 'get_data';

// Capture any output
ob_start();
require 'index.php';
$output = ob_get_clean();

// Check what we got
if (substr($output, 0, 1) === '{') {
    echo "✓ Valid JSON response\n";
    echo "Response length: " . strlen($output) . " characters\n";
} else {
    echo "✗ Invalid response - starts with:\n";
    echo substr($output, 0, 500) . "\n";
    echo "...\n";
}
?>