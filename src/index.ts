import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie } from 'hono/cookie';
import { database } from './firebase';
import { ref, set, get, push, onValue, off } from 'firebase/database';
import bcryptjs from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

const app = new Hono();

// Enable CORS
app.use('/*', cors());

// Session storage (in production, use a proper session store)
const sessions = new Map<string, { userId: string; email: string }>();

// Helper function to generate session token
function generateSessionToken(): string {
  return uuidv4();
}

// Middleware to check authentication
async function requireAuth(c: any, next: any) {
  const sessionToken = getCookie(c, 'session');
  
  if (!sessionToken || !sessions.has(sessionToken)) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  c.set('user', sessions.get(sessionToken));
  await next();
}

// Signup endpoint
app.post('/api/signup', async (c) => {
  try {
    const { email, password, username } = await c.req.json();
    
    if (!email || !password || !username) {
      return c.json({ error: 'Missing required fields' }, 400);
    }
    
    // Check if user already exists
    const usersRef = ref(database, 'users');
    const snapshot = await get(usersRef);
    const users = snapshot.val() || {};
    
    const existingUser = Object.values(users).find((user: any) => user.email === email);
    if (existingUser) {
      return c.json({ error: 'User already exists' }, 400);
    }
    
    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 10);
    
    // Create new user
    const userId = uuidv4();
    const newUser = {
      id: userId,
      email,
      username,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };
    
    await set(ref(database, `users/${userId}`), newUser);
    
    // Create session
    const sessionToken = generateSessionToken();
    sessions.set(sessionToken, { userId, email });
    
    setCookie(c, 'session', sessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 86400 // 24 hours
    });
    
    return c.json({ 
      success: true, 
      user: { id: userId, email, username } 
    });
  } catch (error) {
    console.error('Signup error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Login endpoint
app.post('/api/login', async (c) => {
  try {
    const { email, password } = await c.req.json();
    
    if (!email || !password) {
      return c.json({ error: 'Missing credentials' }, 400);
    }
    
    // Find user by email
    const usersRef = ref(database, 'users');
    const snapshot = await get(usersRef);
    const users = snapshot.val() || {};
    
    const userEntry = Object.entries(users).find(([_, user]: [string, any]) => user.email === email);
    
    if (!userEntry) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }
    
    const [userId, user] = userEntry as [string, any];
    
    // Verify password
    const isValid = await bcryptjs.compare(password, user.password);
    if (!isValid) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }
    
    // Create session
    const sessionToken = generateSessionToken();
    sessions.set(sessionToken, { userId, email });
    
    setCookie(c, 'session', sessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 86400 // 24 hours
    });
    
    return c.json({ 
      success: true, 
      user: { id: userId, email, username: user.username } 
    });
  } catch (error) {
    console.error('Login error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Logout endpoint
app.post('/api/logout', requireAuth, async (c) => {
  const sessionToken = getCookie(c, 'session');
  if (sessionToken) {
    sessions.delete(sessionToken);
  }
  
  setCookie(c, 'session', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 0
  });
  
  return c.json({ success: true });
});

// Get user profile
app.get('/api/profile', requireAuth, async (c) => {
  try {
    const user = c.get('user');
    const userRef = ref(database, `users/${user.userId}`);
    const snapshot = await get(userRef);
    const userData = snapshot.val();
    
    if (!userData) {
      return c.json({ error: 'User not found' }, 404);
    }
    
    return c.json({
      id: userData.id,
      email: userData.email,
      username: userData.username,
      createdAt: userData.createdAt
    });
  } catch (error) {
    console.error('Profile error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Send message
app.post('/api/messages', requireAuth, async (c) => {
  try {
    const user = c.get('user');
    const { recipientId, message } = await c.req.json();
    
    if (!recipientId || !message) {
      return c.json({ error: 'Missing required fields' }, 400);
    }
    
    // Create chat room ID (sorted user IDs)
    const chatRoomId = [user.userId, recipientId].sort().join('-');
    
    // Store message
    const messagesRef = ref(database, `messages/${chatRoomId}`);
    const newMessage = {
      senderId: user.userId,
      recipientId,
      message,
      timestamp: new Date().toISOString()
    };
    
    await push(messagesRef, newMessage);
    
    return c.json({ success: true, message: newMessage });
  } catch (error) {
    console.error('Message error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Get messages
app.get('/api/messages/:recipientId', requireAuth, async (c) => {
  try {
    const user = c.get('user');
    const recipientId = c.req.param('recipientId');
    
    // Create chat room ID
    const chatRoomId = [user.userId, recipientId].sort().join('-');
    
    const messagesRef = ref(database, `messages/${chatRoomId}`);
    const snapshot = await get(messagesRef);
    const messages = snapshot.val() || {};
    
    const messageList = Object.entries(messages).map(([id, msg]: [string, any]) => ({
      id,
      ...msg
    }));
    
    return c.json(messageList);
  } catch (error) {
    console.error('Get messages error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Get all users (for chat list)
app.get('/api/users', requireAuth, async (c) => {
  try {
    const currentUser = c.get('user');
    const usersRef = ref(database, 'users');
    const snapshot = await get(usersRef);
    const users = snapshot.val() || {};
    
    const userList = Object.entries(users)
      .filter(([id, _]) => id !== currentUser.userId)
      .map(([id, user]: [string, any]) => ({
        id,
        username: user.username,
        email: user.email
      }));
    
    return c.json(userList);
  } catch (error) {
    console.error('Get users error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// Serve static files
app.get('/', (c) => c.html(indexHtml));
app.get('/profile', (c) => c.html(profileHtml));
app.get('/chat', (c) => c.html(chatHtml));
app.get('/app.js', (c) => {
  c.header('Content-Type', 'application/javascript');
  return c.text(appJs);
});

export default app;

// HTML templates (normally these would be in separate files)
const indexHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auth App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 {
            text-align: center;
            color: #333;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #666;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .toggle-form {
            text-align: center;
            margin-top: 20px;
            color: #666;
        }
        .toggle-form a {
            color: #007bff;
            text-decoration: none;
        }
        .error {
            color: red;
            margin-top: 10px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 id="formTitle">Login</h2>
        <form id="authForm">
            <div class="form-group" id="usernameGroup" style="display: none;">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username">
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" id="submitBtn">Login</button>
        </form>
        <div class="toggle-form">
            <span id="toggleText">Don't have an account?</span>
            <a href="#" id="toggleLink">Sign up</a>
        </div>
        <div id="error" class="error"></div>
    </div>
    <script src="/app.js"></script>
</body>
</html>`;

const profileHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
        }
        .profile-info {
            margin: 20px 0;
        }
        .profile-info p {
            margin: 10px 0;
            color: #666;
        }
        .profile-info strong {
            color: #333;
        }
        button {
            padding: 10px 20px;
            margin: 5px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        .btn-primary {
            background-color: #007bff;
            color: white;
        }
        .btn-danger {
            background-color: #dc3545;
            color: white;
        }
        button:hover {
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Profile</h1>
        <div id="profileInfo" class="profile-info">
            <p>Loading...</p>
        </div>
        <button class="btn-primary" onclick="window.location.href='/chat'">Go to Chat</button>
        <button class="btn-danger" onclick="logout()">Logout</button>
    </div>
    <script src="/app.js"></script>
    <script>
        loadProfile();
    </script>
</body>
</html>`;

const chatHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            height: 100vh;
            display: flex;
        }
        .sidebar {
            width: 300px;
            background: white;
            border-right: 1px solid #ddd;
            overflow-y: auto;
        }
        .sidebar h3 {
            padding: 20px;
            margin: 0;
            background: #007bff;
            color: white;
        }
        .user-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .user-item {
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
        }
        .user-item:hover {
            background: #f8f9fa;
        }
        .user-item.active {
            background: #e3f2fd;
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        .chat-header {
            background: white;
            padding: 20px;
            border-bottom: 1px solid #ddd;
        }
        .chat-messages {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            background: #fafafa;
        }
        .message {
            margin: 10px 0;
            padding: 10px 15px;
            border-radius: 10px;
            max-width: 70%;
        }
        .message.sent {
            background: #007bff;
            color: white;
            margin-left: auto;
            text-align: right;
        }
        .message.received {
            background: white;
            border: 1px solid #ddd;
        }
        .chat-input {
            display: flex;
            padding: 20px;
            background: white;
            border-top: 1px solid #ddd;
        }
        .chat-input input {
            flex: 1;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-right: 10px;
        }
        .chat-input button {
            padding: 10px 20px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .no-chat {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
        }
        .back-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            padding: 10px 20px;
            background: #6c757d;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <h3>Users</h3>
        <ul id="userList" class="user-list"></ul>
    </div>
    <div class="chat-container">
        <div class="chat-header">
            <h3 id="chatTitle">Select a user to start chatting</h3>
            <a href="/profile" class="back-btn">Back to Profile</a>
        </div>
        <div id="chatArea" class="no-chat">
            <p>Select a user from the list to start a conversation</p>
        </div>
    </div>
    <script src="/app.js"></script>
    <script>
        loadUsers();
    </script>
</body>
</html>`;

const appJs = `
let currentUser = null;
let selectedRecipient = null;
let messageInterval = null;

// Auth form handling
if (document.getElementById('authForm')) {
    const form = document.getElementById('authForm');
    const formTitle = document.getElementById('formTitle');
    const submitBtn = document.getElementById('submitBtn');
    const toggleLink = document.getElementById('toggleLink');
    const toggleText = document.getElementById('toggleText');
    const usernameGroup = document.getElementById('usernameGroup');
    const errorDiv = document.getElementById('error');
    
    let isSignup = false;
    
    toggleLink.addEventListener('click', (e) => {
        e.preventDefault();
        isSignup = !isSignup;
        
        if (isSignup) {
            formTitle.textContent = 'Sign Up';
            submitBtn.textContent = 'Sign Up';
            toggleText.textContent = 'Already have an account?';
            toggleLink.textContent = 'Login';
            usernameGroup.style.display = 'block';
        } else {
            formTitle.textContent = 'Login';
            submitBtn.textContent = 'Login';
            toggleText.textContent = "Don't have an account?";
            toggleLink.textContent = 'Sign up';
            usernameGroup.style.display = 'none';
        }
    });
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errorDiv.textContent = '';
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const username = document.getElementById('username').value;
        
        const endpoint = isSignup ? '/api/signup' : '/api/login';
        const body = isSignup ? { email, password, username } : { email, password };
        
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                window.location.href = '/profile';
            } else {
                errorDiv.textContent = data.error || 'An error occurred';
            }
        } catch (error) {
            errorDiv.textContent = 'Network error. Please try again.';
        }
    });
}

// Profile functions
async function loadProfile() {
    try {
        const response = await fetch('/api/profile', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const user = await response.json();
            currentUser = user;
            document.getElementById('profileInfo').innerHTML = \`
                <p><strong>User ID:</strong> \${user.id}</p>
                <p><strong>Username:</strong> \${user.username}</p>
                <p><strong>Email:</strong> \${user.email}</p>
                <p><strong>Member since:</strong> \${new Date(user.createdAt).toLocaleDateString()}</p>
            \`;
        } else {
            window.location.href = '/';
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        window.location.href = '/';
    }
}

async function logout() {
    try {
        await fetch('/api/logout', {
            method: 'POST',
            credentials: 'include'
        });
        window.location.href = '/';
    } catch (error) {
        console.error('Error logging out:', error);
    }
}

// Chat functions
async function loadUsers() {
    try {
        const response = await fetch('/api/users', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const users = await response.json();
            const userList = document.getElementById('userList');
            
            userList.innerHTML = users.map(user => \`
                <li class="user-item" data-id="\${user.id}" data-username="\${user.username}">
                    <strong>\${user.username}</strong><br>
                    <small>\${user.email}</small>
                </li>
            \`).join('');
            
            // Add click handlers
            document.querySelectorAll('.user-item').forEach(item => {
                item.addEventListener('click', () => selectUser(item));
            });
        } else {
            window.location.href = '/';
        }
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

function selectUser(userElement) {
    // Remove active class from all users
    document.querySelectorAll('.user-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Add active class to selected user
    userElement.classList.add('active');
    
    selectedRecipient = {
        id: userElement.dataset.id,
        username: userElement.dataset.username
    };
    
    // Update chat header
    document.getElementById('chatTitle').textContent = \`Chat with \${selectedRecipient.username}\`;
    
    // Show chat interface
    document.getElementById('chatArea').innerHTML = \`
        <div class="chat-messages" id="chatMessages"></div>
        <div class="chat-input">
            <input type="text" id="messageInput" placeholder="Type a message..." onkeypress="handleKeyPress(event)">
            <button onclick="sendMessage()">Send</button>
        </div>
    \`;
    
    // Load messages and start polling
    loadMessages();
    startMessagePolling();
}

async function loadMessages() {
    if (!selectedRecipient) return;
    
    try {
        const response = await fetch(\`/api/messages/\${selectedRecipient.id}\`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const messages = await response.json();
            displayMessages(messages);
        }
    } catch (error) {
        console.error('Error loading messages:', error);
    }
}

function displayMessages(messages) {
    const messagesDiv = document.getElementById('chatMessages');
    if (!messagesDiv) return;
    
    messagesDiv.innerHTML = messages.map(msg => \`
        <div class="message \${msg.senderId === selectedRecipient.id ? 'received' : 'sent'}">
            <div>\${msg.message}</div>
            <small>\${new Date(msg.timestamp).toLocaleTimeString()}</small>
        </div>
    \`).join('');
    
    // Scroll to bottom
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    
    if (!message || !selectedRecipient) return;
    
    try {
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                recipientId: selectedRecipient.id,
                message
            }),
            credentials: 'include'
        });
        
        if (response.ok) {
            input.value = '';
            loadMessages();
        }
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

function handleKeyPress(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

function startMessagePolling() {
    // Clear existing interval
    if (messageInterval) {
        clearInterval(messageInterval);
    }
    
    // Poll for new messages every 2 seconds
    messageInterval = setInterval(loadMessages, 2000);
}

// Stop polling when leaving the page
window.addEventListener('beforeunload', () => {
    if (messageInterval) {
        clearInterval(messageInterval);
    }
});
`;