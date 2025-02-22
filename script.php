<?php
require_once('auth.php');
date_default_timezone_set("Asia/Kuala_Lumpur");

// Get the JSON input
$data = json_decode(file_get_contents('php://input'), true);

if (isset($data['url']) && filter_var($data['url'], FILTER_VALIDATE_URL)) {
    $websiteUrl = $data['url'];
    $websiteUrl = filter_var($websiteUrl, FILTER_SANITIZE_URL);
} else {
    die("Invalid or missing URL. Please provide a valid URL.");
}

$contextOptions = array(
                "ssl" => array(
                    "verify_peer" => false,
                    "verify_peer_name" => false,
                ),
            );
$context = stream_context_create($contextOptions);

$headers = @get_headers($websiteUrl, 1, $context);
if ($headers === false) {
    die("The URL may be unreachable or invalid.");
}
$headers = get_headers($websiteUrl, 1, $context);
$normalizedHeaders = array_change_key_case($headers, CASE_LOWER);

// Database connection
$servername = "";
$username = "";
$password = "";
$dbname = "";

$conn = new mysqli($servername, $username, $password, $dbname);
      

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$isSecure = false;
$secureHeaders = [
    'x-frame-options' => ['deny', 'sameorigin']
];

// Scan for X-Frame-Options header
foreach ($secureHeaders as $key => $values) {
    if (isset($normalizedHeaders[$key])) {
        $headerValue = $normalizedHeaders[$key];

        if (is_array($headerValue)) {
            foreach ($headerValue as $val) {
                if (in_array(strtolower($val), $values)) {
                    $isSecure = true;
                    break 2;
                }
            }
        } else {
            if (in_array(strtolower($headerValue), $values)) {
                $isSecure = true;
                break;
            }
        }
    }
}

$xfoStatus = $isSecure ? "Present" : "Missing";

// Scan for CSP header
$cspHeader = false;
foreach ($headers as $header => $value) {
    if (stripos($header, 'Content-Security-Policy') !== false) {
        $cspHeader = true;
        break;
    }
}

$cspStatus = $cspHeader ? "Present" : "Missing";

echo "
    <table border='1' style='width:100%; text-align:left;'>
        <tr>
            <th>Header</th>
            <th>Status</th>
        </tr>
        <tr>
            <td>X-Frame-Options</td>
            <td>$xfoStatus</td>
        </tr>
        <tr>
            <td>Content-Security-Policy</td>
            <td>$cspStatus</td>
        </tr>
    </table>
";


// Convert headers to JSON format for storage
$headersJson = base64_encode(json_encode($headers));

if ($isSecure) {
            if (!$cspHeader) {
                echo "<div class='message message-warning'>";
                echo "<i class='fas fa-exclamation-triangle'></i>";
                echo "It is Potential Vulnerable to XSS.";


            } else {
                echo "<div class='message'>";
                echo "<i class='fas fa-lock'></i>";
                echo "It is Safe from Clickjacking Attack.";

            }        
                    
                    // Prepare the SQL statements with placeholders
                    $sqlDelete = "DELETE FROM potentially_vulnerable_urls WHERE website = ?";
                    $sqlCheck = "SELECT * FROM secure_urls WHERE website = ?";
                    $sqlUpdate = "UPDATE secure_urls SET result = ?, UserID = ?, reg_date = ? WHERE website = ?";
                    $sqlInsert = "INSERT INTO secure_urls (website, result, UserID, reg_date) VALUES (?, ?, ?, ?)";
                    
                    // Initialize prepared statements
                    $stmtDelete = $conn->prepare($sqlDelete);
                    $stmtCheck = $conn->prepare($sqlCheck);
                    $stmtUpdate = $conn->prepare($sqlUpdate);
                    $stmtInsert = $conn->prepare($sqlInsert);
                    
                    // Normalize the URL
                    $websiteUrl = trim(preg_replace('/\s+/', ' ', $websiteUrl));

                    
                    $kualaLumpurTimeZone = new DateTimeZone('Asia/Kuala_Lumpur');
                    $currentTime = new DateTime('now', $kualaLumpurTimeZone);
                    $regDate = $currentTime->format('Y-m-d H:i:s');
                    
                    // Check if the URL already exists
                    $stmtCheck->bind_param("s", $websiteUrl);
                    $stmtCheck->execute();
                    $result = $stmtCheck->get_result();
                
                    if ($result->num_rows > 0) {
                        // URL exists, so update the record
                        $stmtUpdate->bind_param("ssss", $headersJson, $_SESSION["user"], $regDate,  $websiteUrl);
                        if ($stmtUpdate->execute()) {
                            
                        } else {
                            echo "Error updating record: " . $conn->error;
                        }
                    } else {
                        // URL does not exist, insert a new record
                        $stmtInsert->bind_param("ssss", $websiteUrl, $headersJson, $_SESSION["user"], $regDate);
                        if ($stmtInsert->execute()) {

                        } else {
                            echo "Error saving record: " . $conn->error;
                        }
                    }
                    
                    // Close statements
                    $stmtDelete->close();
                    $stmtCheck->close();
                    $stmtUpdate->close();
                    $stmtInsert->close();
                
                } else {
                    echo "<div class='message message-vulnerable'>";
                    echo "<i class='fas fa-exclamation-triangle'></i>";
                    echo "It is Vulnerable to Clickjacking Attack.";
                    
                    // Prepare the SQL statements with placeholders
                    $sqlDelete = "DELETE FROM secure_urls WHERE website = ?";
                    $sqlCheck = "SELECT * FROM potentially_vulnerable_urls WHERE website = ?";
                    $sqlUpdate = "UPDATE potentially_vulnerable_urls SET result = ?, UserID = ?, reg_date = ? WHERE website = ?";
                    $sqlInsert = "INSERT INTO potentially_vulnerable_urls (website, result, UserID, reg_date) VALUES (?, ?, ?, ?)";
                    
                    // Initialize prepared statements
                    $stmtDelete = $conn->prepare($sqlDelete);
                    $stmtCheck = $conn->prepare($sqlCheck);
                    $stmtUpdate = $conn->prepare($sqlUpdate);
                    $stmtInsert = $conn->prepare($sqlInsert);
                    
                    // Normalize the URL
                    $websiteUrl = trim(preg_replace('/\s+/', ' ', $websiteUrl));
                    
                    $kualaLumpurTimeZone = new DateTimeZone('Asia/Kuala_Lumpur');
                    $currentTime = new DateTime('now', $kualaLumpurTimeZone);
                    $regDate = $currentTime->format('Y-m-d H:i:s');
                    
                    // Bind parameters and execute the DELETE statement
                    $stmtDelete->bind_param("s", $websiteUrl);
                    $stmtDelete->execute();
                    
                    // Check if the URL already exists in the potentially vulnerable URLs table
                    $stmtCheck->bind_param("s", $websiteUrl);
                    $stmtCheck->execute();
                    $result = $stmtCheck->get_result();
                
                    if ($result->num_rows > 0) {
                        // URL exists, so update the record
                        $stmtUpdate->bind_param("ssss", $headersJson, $_SESSION["user"], $regDate, $websiteUrl);
                        if ($stmtUpdate->execute()) {
                           
                        } else {
                            echo "Error updating record: " . $conn->error;
                        }
                    } else {
                        // URL does not exist, insert a new record
                        $stmtInsert->bind_param("ssss", $websiteUrl, $headersJson, $_SESSION["user"], $regDate);
                        if ($stmtInsert->execute()) {

                        } else {
                            echo "Error saving record: " . $conn->error;
                        }
                    }
                
                    // Close prepared statements
                    $stmtDelete->close();
                    $stmtCheck->close();
                    $stmtUpdate->close();
                    $stmtInsert->close();
                }

?>
