<?php
// index.php - Main entry point
session_start();
$db = new PDO('sqlite:chat.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT,
    avatar TEXT DEFAULT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT CHECK(type IN ('group','channel')) NOT NULL,
    creator_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    sort_order INTEGER DEFAULT 0
)");
$db->exec("CREATE TABLE IF NOT EXISTS group_members (
    user_id INTEGER,
    group_id INTEGER,
    role TEXT DEFAULT 'member',
    PRIMARY KEY(user_id, group_id)
)");
$db->exec("CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT,
    file_name TEXT,
    file_path TEXT,
    file_size INTEGER,
    file_type TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
)");
// Default settings
$db->exec("INSERT OR IGNORE INTO settings (key,value) VALUES ('max_upload_size','2097152')");
$db->exec("INSERT OR IGNORE INTO settings (key,value) VALUES ('allow_registration','1')");

// Helper functions
function isLoggedIn() { return isset($_SESSION['user_id']); }
function isAdmin() { return isset($_SESSION['role']) && $_SESSION['role'] === 'admin'; }
function getSetting($key) { global $db; $s=$db->prepare("SELECT value FROM settings WHERE key=?"); $s->execute([$key]); return $s->fetchColumn(); }

$action = $_GET['action'] ?? 'home';
$response = ['error'=>''];

// Logout action
if ($action === 'logout' && isLoggedIn()) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($action === 'login') {
        $u = $_POST['username'] ?? '';
        $p = $_POST['password'] ?? '';
        $stmt = $db->prepare("SELECT * FROM users WHERE username=?");
        $stmt->execute([$u]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && password_verify($p, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['display_name'] = $user['display_name'] ?: $user['username'];
            $_SESSION['avatar'] = $user['avatar'];
            $_SESSION['role'] = $user['role'];
            header('Location: index.php'); exit;
        } else { $response['error'] = 'Username or password is incorrect'; }
    } elseif ($action === 'register') {
        if (!getSetting('allow_registration')) { $response['error'] = 'Registration is disabled'; }
        else {
            $u = trim($_POST['username'] ?? '');
            $p = $_POST['password'] ?? '';
            $dn = trim($_POST['display_name'] ?? '');
            if (strlen($u)<3 || strlen($p)<4) { $response['error'] = 'Username must be at least 3 characters and password at least 4 characters'; }
            else {
                $hash = password_hash($p, PASSWORD_DEFAULT);
                try {
                    $db->prepare("INSERT INTO users (username,password,display_name,role) VALUES (?,?,?,?)")
                       ->execute([$u, $hash, $dn ?: $u, 'user']);
                    $_SESSION['user_id'] = $db->lastInsertId();
                    $_SESSION['username'] = $u;
                    $_SESSION['display_name'] = $dn ?: $u;
                    $_SESSION['avatar'] = null;
                    $_SESSION['role'] = 'user';
                    header('Location: index.php'); exit;
                } catch(PDOException $e) { $response['error'] = 'Username already exists'; }
            }
        }
    } elseif ($action === 'change_password' && isLoggedIn()) {
        $old = $_POST['old_password'] ?? '';
        $new = $_POST['new_password'] ?? '';
        $stmt = $db->prepare("SELECT password FROM users WHERE id=?");
        $stmt->execute([$_SESSION['user_id']]);
        $row = $stmt->fetch();
        if (!password_verify($old, $row['password'])) { $response['error'] = 'Current password is incorrect'; }
        elseif (strlen($new)<4) { $response['error'] = 'New password must be at least 4 characters'; }
        else {
            $db->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($new,PASSWORD_DEFAULT), $_SESSION['user_id']]);
            $response['success'] = 'Password changed successfully';
        }
    } elseif ($action === 'update_profile' && isLoggedIn()) {
        $dn = trim($_POST['display_name'] ?? '');
        // Handle avatar upload
        if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
            $ext = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
            if (!in_array($ext, ['jpg','jpeg','png','gif','webp'])) { $response['error'] = 'Allowed formats: jpg, png, gif, webp'; }
            elseif ($_FILES['avatar']['size'] > 512000) { $response['error'] = 'Avatar size must be maximum 500 KB'; }
            else {
                $avatarName = 'avatar_'.$_SESSION['user_id'].'_'.time().'.'.$ext;
                move_uploaded_file($_FILES['avatar']['tmp_name'], 'uploads/'.$avatarName);
                $db->prepare("UPDATE users SET avatar=?, display_name=COALESCE(?,username) WHERE id=?")
                   ->execute([$avatarName, $dn ?: null, $_SESSION['user_id']]);
                $_SESSION['avatar'] = $avatarName;
                $_SESSION['display_name'] = $dn ?: $_SESSION['username'];
            }
        } else {
            $db->prepare("UPDATE users SET display_name=COALESCE(?,username) WHERE id=?")
               ->execute([$dn ?: null, $_SESSION['user_id']]);
            $_SESSION['display_name'] = $dn ?: $_SESSION['username'];
        }
        if (!$response['error']) $response['success'] = 'Profile updated successfully';
    } elseif ($action === 'create_group' && isLoggedIn()) {
        $name = trim($_POST['name'] ?? '');
        $type = $_POST['type'] ?? 'group';
        if (strlen($name)<1) { $response['error'] = 'Name is required'; }
        else {
            $db->prepare("INSERT INTO groups (name,type,creator_id) VALUES (?,?,?)")->execute([$name,$type,$_SESSION['user_id']]);
            $gid = $db->lastInsertId();
            $db->prepare("INSERT INTO group_members (user_id,group_id,role) VALUES (?,?,'admin')")->execute([$_SESSION['user_id'],$gid]);
            header('Location: index.php?group='.$gid); exit;
        }
    } elseif ($action === 'send_message' && isLoggedIn()) {
        $gid = (int)($_POST['group_id'] ?? 0);
        $content = trim($_POST['content'] ?? '');
        // Check membership
        $mem = $db->prepare("SELECT 1 FROM group_members WHERE user_id=? AND group_id=?");
        $mem->execute([$_SESSION['user_id'],$gid]);
        if (!$mem->fetch()) { $response['error'] = 'You are not a member of this group'; }
        else {
            $fileData = null;
            if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
                $allowedExts = ['jpg','jpeg','png','gif','webp','mp4','webm','ogg','mp3','wav','zip','rar','pdf'];
                $ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
                $maxSize = (int)getSetting('max_upload_size');
                if (!in_array($ext, $allowedExts)) { $response['error'] = 'File format not allowed'; }
                elseif ($_FILES['file']['size'] > $maxSize) { $response['error'] = 'File size exceeds maximum allowed ('.round($maxSize/1048576,1).' MB)'; }
                else {
                    $fileName = 'file_'.time().'_'.bin2hex(random_bytes(4)).'.'.$ext;
                    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/'.$fileName);
                    $fileData = [
                        'name' => $_FILES['file']['name'],
                        'path' => $fileName,
                        'size' => $_FILES['file']['size'],
                        'type' => $ext
                    ];
                }
            }
            if (!empty($content) || $fileData) {
                $db->prepare("INSERT INTO messages (group_id,user_id,content,file_name,file_path,file_size,file_type) VALUES (?,?,?,?,?,?,?)")
                   ->execute([$gid, $_SESSION['user_id'], $content,
                        $fileData['name']??null, $fileData['path']??null,
                        $fileData['size']??null, $fileData['type']??null]);
            }
            if (!$response['error']) header('Location: index.php?group='.$gid); exit;
        }
    } elseif ($action === 'admin_update_settings' && isAdmin()) {
        if (isset($_POST['max_upload_size'])) {
            $size = (int)$_POST['max_upload_size'];
            $db->prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('max_upload_size',?)")->execute([(string)$size]);
        }
        if (isset($_POST['allow_registration'])) {
            $db->prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('allow_registration','1')")->execute();
        } else {
            $db->prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('allow_registration','0')")->execute();
        }
        $response['success'] = 'Settings saved';
    } elseif ($action === 'admin_delete_user' && isAdmin()) {
        $uid = (int)($_POST['user_id'] ?? 0);
        if ($uid === (int)$_SESSION['user_id']) { $response['error'] = 'You cannot delete yourself'; }
        else { $db->prepare("DELETE FROM users WHERE id=?")->execute([$uid]); }
    } elseif ($action === 'admin_edit_user' && isAdmin()) {
        $uid = (int)($_POST['user_id'] ?? 0);
        $newRole = $_POST['role'] ?? 'user';
        $db->prepare("UPDATE users SET role=? WHERE id=?")->execute([$newRole, $uid]);
    } elseif ($action === 'admin_delete_group' && isAdmin()) {
        $gid = (int)($_POST['group_id'] ?? 0);
        $db->prepare("DELETE FROM messages WHERE group_id=?")->execute([$gid]);
        $db->prepare("DELETE FROM group_members WHERE group_id=?")->execute([$gid]);
        $db->prepare("DELETE FROM groups WHERE id=?")->execute([$gid]);
    } elseif ($action === 'admin_edit_group' && isAdmin()) {
        $gid = (int)($_POST['group_id'] ?? 0);
        $name = trim($_POST['name'] ?? '');
        $sort = (int)($_POST['sort_order'] ?? 0);
        if ($name) $db->prepare("UPDATE groups SET name=?, sort_order=? WHERE id=?")->execute([$name, $sort, $gid]);
    } elseif ($action === 'join_group' && isLoggedIn()) {
        $gid = (int)($_POST['group_id'] ?? 0);
        // Allow anyone to join both groups and channels
        $db->prepare("INSERT OR IGNORE INTO group_members (user_id,group_id) VALUES (?,?)")->execute([$_SESSION['user_id'], $gid]);
    } elseif ($action === 'leave_group' && isLoggedIn()) {
        $gid = (int)($_POST['group_id'] ?? 0);
        // Cannot leave if last admin? Fallback: allow leave
        $db->prepare("DELETE FROM group_members WHERE user_id=? AND group_id=?")->execute([$_SESSION['user_id'], $gid]);
    }
    // Redirect to avoid resubmission
    if (!$response['error'] && !isset($response['success'])) {
        header('Location: index.php'.(isset($_GET['group'])?'?group='.(int)$_GET['group']:''));
        exit;
    }
}

// ---- RENDER HTML ----
if (!isLoggedIn() && $action !== 'login' && $action !== 'register') $action = 'login';
$currentGroup = isset($_GET['group']) ? (int)$_GET['group'] : 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lumina Chat</title>
    <link rel="icon" href="favico.png"/>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div id="app">
        <!-- Sidebar -->
        <aside id="sidebar">
            <div class="sidebar-header">
                <h2>Lumina Chat</h2>
                <button id="close-sidebar">✕</button>
            </div>
            <?php if (isLoggedIn()): ?>
            <div class="user-info">
                <img src="<?= $_SESSION['avatar'] ? 'uploads/'.htmlspecialchars($_SESSION['avatar']) : 'default-avatar.png' ?>" class="avatar-sm">
                <span><?= htmlspecialchars($_SESSION['display_name']) ?></span>
                <a href="index.php?action=profile" class="btn-small">Edit</a>
            </div>
            <nav>
                <a href="index.php" class="nav-link">Home</a>
                <a href="index.php?action=groups" class="nav-link">Groups</a>
                <?php if (isAdmin()): ?>
                    <a href="index.php?action=admin" class="nav-link">Admin</a>
                <?php endif; ?>
                <a href="index.php?action=logout" class="nav-link">Logout</a>
            </nav>
            <?php endif; ?>
            
            <!-- My Channels & Groups Section in Sidebar -->
            <div class="group-list">
                <?php if (isLoggedIn()):
                    // Get user's channels
                    $channels = $db->prepare("SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count FROM groups g JOIN group_members m ON g.id=m.group_id WHERE m.user_id=? AND g.type='channel' ORDER BY g.sort_order, g.name");
                    $channels->execute([$_SESSION['user_id']]);
                    
                    // Get user's groups
                    $groups = $db->prepare("SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count FROM groups g JOIN group_members m ON g.id=m.group_id WHERE m.user_id=? AND g.type='group' ORDER BY g.sort_order, g.name");
                    $groups->execute([$_SESSION['user_id']]);
                    
                    // Display Channels section (always show)
                    ?>
                    <h3>My Channels</h3>
                    <?php 
                    $hasChannels = false;
                    foreach ($channels as $g):
                        $hasChannels = true;
                    ?>
                        <a href="index.php?group=<?= $g['id'] ?>" class="group-item <?= $currentGroup==$g['id']?'active':'' ?>">
                            <span># <?= htmlspecialchars($g['name']) ?></span>
                            <span class="badge"><?= $g['member_count'] ?></span>
                        </a>
                    <?php endforeach; ?>
                    <?php if (!$hasChannels): ?>
                        <p class="empty-message" style="font-size:0.8em; color:#888; padding:5px 10px;">No channels joined yet.</p>
                    <?php endif;
                    
                    // Display Groups section (always show)
                    ?>
                    <h3>My Groups</h3>
                    <?php 
                    $hasGroups = false;
                    foreach ($groups as $g):
                        $hasGroups = true;
                    ?>
                        <a href="index.php?group=<?= $g['id'] ?>" class="group-item <?= $currentGroup==$g['id']?'active':'' ?>">
                            <span>📌 <?= htmlspecialchars($g['name']) ?></span>
                            <span class="badge"><?= $g['member_count'] ?></span>
                        </a>
                    <?php endforeach; ?>
                    <?php if (!$hasGroups): ?>
                        <p class="empty-message" style="font-size:0.8em; color:#888; padding:5px 10px;">No groups joined yet.</p>
                    <?php endif;
                endif; ?>
            </div>
        </aside>

        <!-- Main content -->
        <main id="main">
            <header class="topbar">
                <button id="menu-toggle">☰</button>
                <?php if ($currentGroup): 
                    $grp = $db->prepare("SELECT * FROM groups WHERE id=?");
                    $grp->execute([$currentGroup]);
                    $g = $grp->fetch();
                    if ($g): ?>
                        <h1><?= htmlspecialchars($g['name']) ?></h1>
                        <span class="group-type"><?= $g['type'] === 'channel' ? 'Channel' : 'Group' ?></span>
                    <?php endif; ?>
                <?php else: ?>
                    <h1>Welcome</h1>
                <?php endif; ?>
                <?php if (isLoggedIn()): ?>
                <div class="topbar-actions">
                    <a href="" id="renew-message"><strong>🔄 Refresh</strong></a>
                </div>
                <div class="topbar-actions">
                    <button id="theme-toggle">🌙</button>
                </div>
                <?php endif; ?>
            </header>

            <div class="content">
                <?php if (!isLoggedIn() && $action === 'login'): ?>
                    <!-- Login form -->
                    <div class="auth-form">
                        <h2>Login</h2>
                        <?php if ($response['error']): ?><div class="error"><?= $response['error'] ?></div><?php endif; ?>
                        <form method="post" action="index.php?action=login">
                            <input type="text" name="username" placeholder="Username" required>
                            <input type="password" name="password" placeholder="Password" required>
                            <button type="submit">Login</button>
                        </form>
                        <a href="index.php?action=register">Register</a>
                    </div>
                <?php elseif (!isLoggedIn() && $action === 'register'): ?>
                    <div class="auth-form">
                        <h2>Register</h2>
                        <?php if ($response['error']): ?><div class="error"><?= $response['error'] ?></div><?php endif; ?>
                        <form method="post" action="index.php?action=register">
                            <input type="text" name="username" placeholder="Username" required>
                            <input type="password" name="password" placeholder="Password" required>
                            <input type="text" name="display_name" placeholder="Display Name (Optional)">
                            <button type="submit">Register</button>
                        </form>
                        <a href="index.php?action=login">Login</a>
                    </div>
                <?php elseif ($action === 'profile' && isLoggedIn()): ?>
    <div class="profile-page">
        <h2>Profile</h2>
        <?php if ($response['error']): ?><div class="error"><?= $response['error'] ?></div><?php endif; ?>
        <?php if (isset($response['success'])): ?><div class="success"><?= $response['success'] ?></div><?php endif; ?>
        
        <form method="post" action="index.php?action=update_profile" enctype="multipart/form-data" class="profile-form">
            <label>Avatar (Max 500 KB)</label>
            <input type="file" name="avatar" accept="image/*">
            <label>Display Name</label>
            <input type="text" name="display_name" value="<?= htmlspecialchars($_SESSION['display_name'] ?? '') ?>" placeholder="Display Name">
            <button type="submit">Save</button>
        </form>
        
        <hr>
        <h3>Change Password</h3>
        <form method="post" action="index.php?action=change_password" class="profile-form">
            <input type="password" name="old_password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <button type="submit">Change Password</button>
        </form>
    </div>

<?php elseif ($action === 'groups' && isLoggedIn()): ?>
    <div class="groups-page">
        <h2>Groups & Channels</h2>
        <?php if ($response['error']): ?><div class="error"><?= $response['error'] ?></div><?php endif; ?>
        
        <div class="create-group-form">
            <h3>Create New Group or Channel</h3>
            <form method="post" action="index.php?action=create_group">
                <input type="text" name="name" placeholder="Group/Channel Name" required>
                <select name="type">
                    <option value="group">Group</option>
                    <option value="channel">Channel</option>
                </select>
                <button type="submit">Create</button>
            </form>
        </div>
        
        <hr>
        
        <!-- All Channels Section -->
        <div class="group-list-all">
            <h3>All Channels</h3>
            <?php 
            $allChannels = $db->query("SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count FROM groups g WHERE g.type='channel' ORDER BY g.sort_order, g.name");
            $hasChannels = false;
            foreach ($allChannels as $g):
                $hasChannels = true;
                // Check membership
                $check = $db->prepare("SELECT 1 FROM group_members WHERE user_id=? AND group_id=?");
                $check->execute([$_SESSION['user_id'], $g['id']]);
                $isMember = $check->fetch();
            ?>
            <div class="group-card">
                <div>
                    <strong># <?= htmlspecialchars($g['name']) ?></strong>
                    <span class="badge">Channel</span>
                    <span class="member-count"><?= $g['member_count'] ?> members</span>
                </div>
                <div>
                    <?php if ($isMember): ?>
                        <form method="post" action="index.php?action=leave_group" style="display:inline">
                            <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                            <button type="submit" class="btn-small btn-danger">Leave</button>
                        </form>
                        <a href="index.php?group=<?= $g['id'] ?>" class="btn-small">Enter</a>
                    <?php else: ?>
                        <form method="post" action="index.php?action=join_group" style="display:inline">
                            <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                            <button type="submit" class="btn-small">Join</button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
            <?php if (!$hasChannels): ?>
                <p class="empty-message">No channels yet. Create one!</p>
            <?php endif; ?>
        </div>
        
        <!-- All Groups Section -->
        <div class="group-list-all">
            <h3>All Groups</h3>
            <?php 
            $allGroups = $db->query("SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count FROM groups g WHERE g.type='group' ORDER BY g.sort_order, g.name");
            $hasGroups = false;
            foreach ($allGroups as $g):
                $hasGroups = true;
                // Check membership
                $check = $db->prepare("SELECT 1 FROM group_members WHERE user_id=? AND group_id=?");
                $check->execute([$_SESSION['user_id'], $g['id']]);
                $isMember = $check->fetch();
            ?>
            <div class="group-card">
                <div>
                    <strong>📌 <?= htmlspecialchars($g['name']) ?></strong>
                    <span class="badge">Group</span>
                    <span class="member-count"><?= $g['member_count'] ?> members</span>
                </div>
                <div>
                    <?php if ($isMember): ?>
                        <form method="post" action="index.php?action=leave_group" style="display:inline">
                            <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                            <button type="submit" class="btn-small btn-danger">Leave</button>
                        </form>
                        <a href="index.php?group=<?= $g['id'] ?>" class="btn-small">Enter</a>
                    <?php else: ?>
                        <form method="post" action="index.php?action=join_group" style="display:inline">
                            <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                            <button type="submit" class="btn-small">Join</button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
            <?php if (!$hasGroups): ?>
                <p class="empty-message">No groups yet. Create one!</p>
            <?php endif; ?>
        </div>
    </div>

<?php elseif ($action === 'admin' && isAdmin()): ?>
    <div class="admin-page">
        <h2>Admin Panel</h2>
        <?php if ($response['error']): ?><div class="error"><?= $response['error'] ?></div><?php endif; ?>
        <?php if (isset($response['success'])): ?><div class="success"><?= $response['success'] ?></div><?php endif; ?>
        
        <div class="admin-section">
            <h3>Site Settings</h3>
            <form method="post" action="index.php?action=admin_update_settings">
                <label>Max Upload Size (Bytes) - Current: <?= number_format((int)getSetting('max_upload_size')) ?> bytes</label>
                <input type="number" name="max_upload_size" value="<?= (int)getSetting('max_upload_size') ?>" min="1" max="104857600">
                <label>
                    <input type="checkbox" name="allow_registration" value="1" <?= getSetting('allow_registration') === '1' ? 'checked' : '' ?>>
                    Enable Registration
                </label>
                <button type="submit">Save Settings</button>
            </form>
        </div>
        
        <div class="admin-section">
            <h3>Users</h3>
            <div class="admin-list">
                <?php 
                $users = $db->query("SELECT id, username, display_name, role FROM users ORDER BY id");
                foreach ($users as $u): ?>
                <div class="admin-item">
                    <span><?= htmlspecialchars($u['display_name'] ?: $u['username']) ?> (<?= $u['role'] ?>)</span>
                    <div>
                        <form method="post" action="index.php?action=admin_edit_user" style="display:inline">
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                            <select name="role">
                                <option value="user" <?= $u['role']==='user'?'selected':'' ?>>User</option>
                                <option value="admin" <?= $u['role']==='admin'?'selected':'' ?>>Admin</option>
                            </select>
                            <button type="submit" class="btn-small">Change Role</button>
                        </form>
                        <?php if ($u['id'] !== (int)$_SESSION['user_id']): ?>
                        <form method="post" action="index.php?action=admin_delete_user" style="display:inline" onsubmit="return confirm('Delete this user?')">
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                            <button type="submit" class="btn-small btn-danger">Delete</button>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div class="admin-section">
            <h3>Groups & Channels</h3>
            <div class="admin-list">
                <?php 
                $groups = $db->query("SELECT * FROM groups ORDER BY type DESC, sort_order, name");
                foreach ($groups as $g): ?>
                <div class="admin-item">
                    <form method="post" action="index.php?action=admin_edit_group" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
                        <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                        <span class="group-type-badge"><?= $g['type'] === 'channel' ? '#' : '📌' ?></span>
                        <input type="text" name="name" value="<?= htmlspecialchars($g['name']) ?>" style="width:200px">
                        <input type="number" name="sort_order" value="<?= $g['sort_order'] ?>" style="width:60px" placeholder="Sort Order">
                        <button type="submit" class="btn-small">Save</button>
                    </form>
                    <form method="post" action="index.php?action=admin_delete_group" style="display:inline" onsubmit="return confirm('Delete this group?')">
                        <input type="hidden" name="group_id" value="<?= $g['id'] ?>">
                        <button type="submit" class="btn-small btn-danger">Delete</button>
                    </form>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

<?php elseif ($currentGroup && isLoggedIn()): ?>
    <!-- Chat view -->
    <div class="chat-view">
        <div id="messages" class="messages-container">
            <?php 
            $msgs = $db->prepare("SELECT m.*, u.display_name as uname, u.avatar as uavatar FROM messages m JOIN users u ON m.user_id=u.id WHERE m.group_id=? ORDER BY m.created_at ASC LIMIT 200");
            $msgs->execute([$currentGroup]);
            foreach ($msgs as $msg):
                // Global date formatting
                $dt = new DateTime($msg['created_at'] ?? 'now', new DateTimeZone('UTC'));
                $dt->setTimezone(new DateTimeZone('UTC'));
                $dateTime = $dt->format('Y-m-d H:i:s');
                $isOwn = $msg['user_id'] == $_SESSION['user_id'];
            ?>
            <div class="message <?= $isOwn ? 'own' : '' ?>">
                <div class="msg-header">
                    <img src="<?= $msg['uavatar'] ? 'uploads/'.htmlspecialchars($msg['uavatar']) : 'default-avatar.png' ?>" class="avatar-xs">
                    <strong><?= htmlspecialchars($msg['uname'] ?: $msg['username']) ?></strong>
                    <span class="msg-time"><?= $dateTime ?></span>
                </div>
                <?php if ($msg['content']): ?>
                    <div class="msg-text"><?= nl2br(htmlspecialchars($msg['content'])) ?></div>
                <?php endif; ?>
                <?php if ($msg['file_path']): 
                    $imgExts = ['jpg','jpeg','png','gif','webp'];
                    $isImg = in_array($msg['file_type'], $imgExts);
                ?>
                    <div class="msg-attachment">
                        <?php if ($isImg): ?>
                            <img src="uploads/<?= htmlspecialchars($msg['file_path']) ?>" class="chat-image" onclick="openImage(this.src)" loading="lazy">
                        <?php else: ?>
                            <div class="file-info">
                                <span class="file-icon">📎</span>
                                <span class="file-name"><?= htmlspecialchars($msg['file_name']) ?></span>
                                <span class="file-size">(<?= round($msg['file_size']/1024, 1) ?> KB)</span>
                                <a href="uploads/<?= htmlspecialchars($msg['file_path']) ?>" download class="btn-small">Download</a>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        
        <!-- Message input -->
        <?php 
        $isMemberCheck = $db->prepare("SELECT 1 FROM group_members WHERE user_id=? AND group_id=?");
        $isMemberCheck->execute([$_SESSION['user_id'], $currentGroup]);
        $isMember = $isMemberCheck->fetch();
        if ($isMember): 
        $grpCheck = $db->prepare("SELECT type, creator_id FROM groups WHERE id=?");
        $grpCheck->execute([$currentGroup]);
        $grp = $grpCheck->fetch();
        
        // Check if user can send messages
        // For channels: only creator or admin can send
        // For groups: all members can send
        $isCreator = ($grp && $grp['creator_id'] == $_SESSION['user_id']);
        $isAdminUser = isAdmin();
        if ($grp && $grp['type'] === 'channel') {
            $canSend = ($isCreator || $isAdminUser);
        } else {
            $canSend = true;
        }
        
        if ($canSend): ?>
        <form method="post" action="index.php?action=send_message" enctype="multipart/form-data" class="message-form">
            <input type="hidden" name="group_id" value="<?= $currentGroup ?>">
            <div class="input-group">
                <textarea name="content" id="msg-input" placeholder="Type your message..." autocomplete="off" rows="3"></textarea>
                <label class="file-label">
                    📎
                    <input type="file" name="file" onchange="updateFileName(this)" style="display:none">
                </label>
                <button type="submit">Send</button>
            </div>
            <div id="file-name-display" style="font-size:0.8em;padding:4px;"></div>
        </form>
        <?php else: ?>
            <p style="text-align:center;padding:10px;color:#888;">This channel is read-only. Only the creator and admins can send messages.</p>
        <?php endif; endif; ?>
    </div>

<?php else: ?>
    <!-- Home page -->
    <div class="home-page">
        <h2>Welcome to the Chat</h2>
        <p>Select a group from the sidebar or create a new group.</p>
        <a href="index.php?action=groups" class="btn">View Groups</a>
    </div>
<?php endif; ?>

            </div><!-- end .content -->
        </main>
    </div><!-- end #app -->

    <!-- Image lightbox -->
    <div id="lightbox" onclick="this.style.display='none'" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;display:none;justify-content:center;align-items:center;cursor:pointer;">
        <img id="lightbox-img" style="max-width:90%;max-height:90%;object-fit:contain;">
    </div>

    <script src="script.js"></script>
</body>
</html>
