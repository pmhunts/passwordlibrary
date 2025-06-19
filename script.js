// DOM Elements
const authContainer = document.getElementById('authContainer');
const authTitle = document.getElementById('authTitle');
const authForm = document.getElementById('authForm');
const authButton = document.getElementById('authButton');
const authToggleText = document.getElementById('authToggleText');
const authToggleLink = document.getElementById('authToggleLink');
const confirmPasswordGroup = document.getElementById('confirmPasswordGroup');
const passwordManager = document.getElementById('passwordManager');
const currentUser = document.getElementById('currentUser');
const logoutBtn = document.getElementById('logoutBtn');
const addNewBtn = document.getElementById('addNewBtn');
const exportBtn = document.getElementById('exportBtn');
const searchInput = document.getElementById('searchInput');
const passwordTableBody = document.getElementById('passwordTableBody');
const emptyState = document.getElementById('emptyState');
const passwordModal = document.getElementById('passwordModal');
const closeModal = document.getElementById('closeModal');
const passwordForm = document.getElementById('passwordForm');
const modalTitle = document.getElementById('modalTitle');
const passwordId = document.getElementById('passwordId');
const generatePasswordBtn = document.getElementById('generatePassword');
const passwordField = document.getElementById('passwordField');
const strengthText = document.getElementById('strengthText');
const strengthIndicator = document.getElementById('strengthIndicator');

// API Base URL - change this to your server URL in production
const API_BASE_URL = 'https://passwordmanager-9rsw.onrender.com';

// State variables
let isLogin = true;
let currentUserId = null;
let currentUserToken = null;
let currentUsername = null;
let passwordEntries = [];
let editingEntryId = null;

// Toggle between login and register forms
authToggleLink.addEventListener('click', () => {
    isLogin = !isLogin;
    
    if (isLogin) {
        authTitle.textContent = 'Log In';
        authButton.textContent = 'Log In';
        authToggleText.textContent = "Don't have an account?";
        authToggleLink.textContent = 'Sign up';
        confirmPasswordGroup.style.display = 'none';
        document.getElementById('confirmPassword').required = false;
    } else {
        authTitle.textContent = 'Register';
        authButton.textContent = 'Register';
        authToggleText.textContent = 'Already have an account?';
        authToggleLink.textContent = 'Log in';
        confirmPasswordGroup.style.display = 'block';
        document.getElementById('confirmPassword').required = true;
    }
});

// Enhanced form submission handling
function initializeAuthForm() {
    console.log("Initializing auth form handler");

    if (!authForm || !(authForm instanceof HTMLElement)) {
        console.error("Auth form element not found or invalid");
        return;
    }

    try {
        authForm.addEventListener('submit', handleFormSubmit);
        console.log("Submit event listener attached successfully");
    } catch (error) {
        console.error("Error attaching submit listener:", error);
    }
}

async function handleFormSubmit(e) {
    if (e) e.preventDefault();
    console.log("Form submit handler triggered");

    try {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) {
            alert("Please enter both username and password.");
            return;
        }

        if (isLogin) {
            console.log("Attempting login for:", username);
            
            try {
const response = await fetch(`${API_BASE_URL}/api/users/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Invalid username or password');
                }
                
                const data = await response.json();
                loginUser(data.user, data.token);
            } catch (error) {
                alert(error.message || 'Login failed. Please try again.');
            }
        } else {
            const confirmPassword = document.getElementById('confirmPassword').value;

            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }

            try {
const response = await fetch(`${API_BASE_URL}/api/users/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Registration failed');
                }
                
                alert('Registration successful! You can now log in.');
                authToggleLink.click(); // Switch to login view
            } catch (error) {
                alert(error.message || 'Registration failed. Please try again.');
            }
        }
    } catch (error) {
        console.error("Error in form submission:", error);
        alert("An unexpected error occurred. Please try again.");
    }
}

// Initialize form handling
initializeAuthForm();

// Login/logout functions
function loginUser(user, token) {
    currentUserId = user.id;
    currentUsername = user.username;
    currentUserToken = token;
    
    // Update UI
    currentUser.textContent = currentUsername;
    
    // Store session (token only, not passwords)
    sessionStorage.setItem('currentUserId', currentUserId);
    sessionStorage.setItem('currentUsername', currentUsername);
    sessionStorage.setItem('currentUserToken', currentUserToken);
    
    // Show password manager UI
    authContainer.style.display = 'none';
    passwordManager.style.display = 'block';
    
    // Load user's password entries
    loadPasswordEntries();
}

function logoutUser() {
    console.log("Logout user called");
    currentUserId = null;
    currentUsername = null;
    currentUserToken = null;
    passwordEntries = [];
    
    // Clear session
    sessionStorage.removeItem('currentUserId');
    sessionStorage.removeItem('currentUsername');
    sessionStorage.removeItem('currentUserToken');
    
    // Show login UI
    passwordManager.style.display = 'none';
    authContainer.style.display = 'block';

    // Reset to login form state
    isLogin = true;
    authTitle.textContent = 'Log In';
    authButton.textContent = 'Log In';
    authToggleText.textContent = "Don't have an account?";
    authToggleLink.textContent = 'Sign up';
    confirmPasswordGroup.style.display = 'none';
    
    // Clear form fields
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('confirmPassword').value = '';

    // Re-initialize form event listener to ensure it is attached
    initializeAuthForm();
}

// Password entry management
async function loadPasswordEntries() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/passwords`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${currentUserToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load passwords');
        }
        
        const data = await response.json();
        passwordEntries = data.passwordEntries;
        
        // Render password list
        renderPasswordList();
    } catch (error) {
        console.error('Error loading passwords:', error);
        alert('Error loading your passwords. Please try logging in again.');
        logoutUser();
    }
}

function renderPasswordList() {
    // Clear table
    passwordTableBody.innerHTML = '';
    
    if (passwordEntries.length === 0) {
        // Show empty state
        emptyState.style.display = 'block';
        document.getElementById('passwordList').style.display = 'none';
        return;
    }
    
    // Hide empty state, show table
    emptyState.style.display = 'none';
    document.getElementById('passwordList').style.display = 'block';
    
    // Filter by search term
    const searchTerm = searchInput.value.toLowerCase();
    const filteredEntries = passwordEntries.filter(entry => 
        entry.website.toLowerCase().includes(searchTerm) || 
        entry.username.toLowerCase().includes(searchTerm)
    );
    
    // Render entries
    filteredEntries.forEach(entry => {
        const row = document.createElement('tr');
        row.dataset.entryId = entry.id;
        
        // Website column
        const websiteCell = document.createElement('td');
        websiteCell.textContent = entry.website;
        row.appendChild(websiteCell);
        
        // Username column
        const usernameCell = document.createElement('td');
        usernameCell.textContent = entry.username;
        row.appendChild(usernameCell);
        
        // Password column (masked)
        const passwordCell = document.createElement('td');
        passwordCell.className = 'password-field';
        
        const maskedPassword = document.createElement('span');
        maskedPassword.textContent = '••••••••';
        maskedPassword.className = 'masked-password';
        
        const showPasswordBtn = document.createElement('span');
        showPasswordBtn.textContent = '👁️';
        showPasswordBtn.title = 'Show password';
        showPasswordBtn.onclick = () => togglePasswordVisibility(entry.id, showPasswordBtn);
        
        passwordCell.appendChild(maskedPassword);
        passwordCell.appendChild(showPasswordBtn);
        row.appendChild(passwordCell);
        
        // Last updated column
        const lastUpdatedCell = document.createElement('td');
        lastUpdatedCell.textContent = new Date(entry.lastUpdated).toLocaleDateString();
        row.appendChild(lastUpdatedCell);
        
        // Actions column
        const actionsCell = document.createElement('td');
        actionsCell.className = 'action-cell';
        
        const copyBtn = document.createElement('button');
        copyBtn.textContent = 'Copy';
        copyBtn.onclick = () => copyPassword(entry.password);
        
        const editBtn = document.createElement('button');
        editBtn.textContent = 'Edit';
        editBtn.onclick = () => editPasswordEntry(entry.id);
        
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'Delete';
        deleteBtn.style.backgroundColor = '#f44336';
        deleteBtn.onclick = () => deletePasswordEntry(entry.id);
        
        actionsCell.appendChild(copyBtn);
        actionsCell.appendChild(editBtn);
        actionsCell.appendChild(deleteBtn);
        row.appendChild(actionsCell);
        
        passwordTableBody.appendChild(row);
    });
}

// Toggle password visibility
function togglePasswordVisibility(entryId, button) {
    const entry = passwordEntries.find(entry => entry.id === entryId);
    if (!entry) return;
    
    const row = button.closest('tr');
    const maskedPassword = row.querySelector('.masked-password');
    
    if (maskedPassword.textContent === '••••••••') {
        maskedPassword.textContent = entry.password;
        button.textContent = '🔒';
        button.title = 'Hide password';
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            maskedPassword.textContent = '••••••••';
            button.textContent = '👁️';
            button.title = 'Show password';
        }, 5000);
    } else {
        maskedPassword.textContent = '••••••••';
        button.textContent = '👁️';
        button.title = 'Show password';
    }
}

// Copy password to clipboard
function copyPassword(password) {
    navigator.clipboard.writeText(password)
        .then(() => {
            alert('Password copied to clipboard!');
        })
        .catch(err => {
            console.error('Failed to copy password: ', err);
            alert('Failed to copy password');
        });
}

// Add new password entry
function addNewPasswordEntry() {
    editingEntryId = null;
    modalTitle.textContent = 'Add New Password';
    
    // Clear form
    passwordForm.reset();
    passwordId.value = '';
    
    // Reset strength indicator
    strengthIndicator.style.width = '0%';
    strengthIndicator.style.backgroundColor = '#ccc';
    strengthText.textContent = 'Strength: ';
    
    // Show modal
    passwordModal.style.display = 'flex';
}

// Edit password entry
function editPasswordEntry(entryId) {
    const entry = passwordEntries.find(entry => entry.id === entryId);
    if (!entry) return;
    
    editingEntryId = entryId;
    modalTitle.textContent = 'Edit Password';
    
    // Fill form with entry data
    document.getElementById('website').value = entry.website;
    document.getElementById('websiteUrl').value = entry.url || '';
    document.getElementById('usernameField').value = entry.username;
    document.getElementById('passwordField').value = entry.password;
    document.getElementById('notes').value = entry.notes || '';
    passwordId.value = entryId;
    
    // Update strength indicator
    checkPasswordStrength(entry.password);
    
    // Show modal
    passwordModal.style.display = 'flex';
}

// Delete password entry
async function deletePasswordEntry(entryId) {
    if (!confirm('Are you sure you want to delete this password entry?')) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/passwords/${entryId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${currentUserToken}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to delete password entry');
        }
        
        // Remove from local array
        passwordEntries = passwordEntries.filter(entry => entry.id !== entryId);
        
        // Refresh list
        renderPasswordList();
    } catch (error) {
        console.error('Error deleting password:', error);
        alert('Error deleting password entry. Please try again.');
    }
}

// Generate strong password
function generateStrongPassword() {
    const length = 16;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[]|:;<>,.?/';
    let password = '';
    
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    
    passwordField.value = password;
    checkPasswordStrength(password);
}

// Check password strength
function checkPasswordStrength(password) {
    // Basic password strength calculation
    let strength = 0;
    
    // Length check
    if (password.length >= 8) strength += 20;
    if (password.length >= 12) strength += 10;
    
    // Character variety checks
    if (/[a-z]/.test(password)) strength += 15; // lowercase
    if (/[A-Z]/.test(password)) strength += 15; // uppercase
    if (/[0-9]/.test(password)) strength += 15; // numbers
    if (/[^a-zA-Z0-9]/.test(password)) strength += 15; // special chars
    
    // No sequential characters or repetitions
    if (!/(.)\1\1/.test(password)) strength += 10; // no triple characters
    
    // Update UI
    strengthIndicator.style.width = `${strength}%`;
    strengthText.textContent = `Strength: ${getStrengthLabel(strength)}`;
    
    // Update color
    if (strength < 40) {
        strengthIndicator.style.backgroundColor = '#ff5252'; // weak
    } else if (strength < 70) {
        strengthIndicator.style.backgroundColor = '#ffd740'; // medium
    } else {
        strengthIndicator.style.backgroundColor = '#4caf50'; // strong
    }
}

function getStrengthLabel(strength) {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
}

// Export password data
function exportPasswordData() {
    if (passwordEntries.length === 0) {
        alert('No password data to export');
        return;
    }
    
    const exportData = {
        exportDate: new Date().toISOString(),
        entries: passwordEntries.map(entry => ({
            website: entry.website,
            url: entry.url,
            username: entry.username,
            password: entry.password,
            notes: entry.notes,
            lastUpdated: entry.lastUpdated
        }))
    };
    
    const jsonString = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `password-export-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Event Listeners
// Modal close button
closeModal.addEventListener('click', () => {
    passwordModal.style.display = 'none';
});

// Click outside modal to close
passwordModal.addEventListener('click', (e) => {
    if (e.target === passwordModal) {
        passwordModal.style.display = 'none';
    }
});

// Add new password button
addNewBtn.addEventListener('click', addNewPasswordEntry);

// Export button
exportBtn.addEventListener('click', exportPasswordData);

// Logout button
logoutBtn.addEventListener('click', logoutUser);

// Generate password button
generatePasswordBtn.addEventListener('click', generateStrongPassword);

// Password field input - check strength
passwordField.addEventListener('input', (e) => {
    checkPasswordStrength(e.target.value);
});

// Search input
searchInput.addEventListener('input', renderPasswordList);

// Password form submission
passwordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const websiteValue = document.getElementById('website').value;
    const urlValue = document.getElementById('websiteUrl').value;
    const usernameValue = document.getElementById('usernameField').value;
    const passwordValue = document.getElementById('passwordField').value;
    const notesValue = document.getElementById('notes').value;
    
    // Basic validation
    if (!websiteValue || !usernameValue || !passwordValue) {
        alert('Please fill in all required fields');
        return;
    }
    
    try {
        if (editingEntryId) {
            // Update existing entry
            const response = await fetch(`${API_BASE_URL}/api/passwords/${editingEntryId}`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentUserToken}`
                },
                body: JSON.stringify({
                    website: websiteValue,
                    url: urlValue,
                    username: usernameValue,
                    password: passwordValue,
                    notes: notesValue
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to update password entry');
            }
            
            const data = await response.json();
            
            // Update local array
            const entryIndex = passwordEntries.findIndex(entry => entry.id === editingEntryId);
            if (entryIndex >= 0) {
                passwordEntries[entryIndex] = data.entry;
            }
        } else {
            // Add new entry
            const response = await fetch(`${API_BASE_URL}/api/passwords`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentUserToken}`
                },
                body: JSON.stringify({
                    website: websiteValue,
                    url: urlValue,
                    username: usernameValue,
                    password: passwordValue,
                    notes: notesValue
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to add password entry');
            }
            
            const data = await response.json();
            
            // Add to local array
            passwordEntries.push(data.entry);
        }
        
        // Refresh list
        renderPasswordList();
        
        // Close modal
        passwordModal.style.display = 'none';
    } catch (error) {
        console.error('Error saving password:', error);
        alert('Error saving password entry. Please try again.');
    }
});

// Add keyboard shortcut (Ctrl+F or Cmd+F) to focus search
document.addEventListener('keydown', (e) => {
    // Check if Ctrl key (Windows) or Command key (Mac) is pressed along with F
    if ((e.ctrlKey || e.metaKey) && e.key === 'f' && currentUserId) {
        e.preventDefault(); // Prevent browser's default search behavior
        searchInput.focus();
    }
});

// Add double-click handler for password cells to quickly copy passwords
document.addEventListener('dblclick', (e) => {
    // Check if the clicked element is part of a password row
    const row = e.target.closest('tr');
    if (row && passwordTableBody.contains(row)) {
        const entryId = row.dataset.entryId;
        
        if (entryId) {
            const entry = passwordEntries.find(e => e.id === entryId);
            
            if (entry) {
                copyPassword(entry.password);
            }
        }
    }
});

// Check for existing session on page load
function checkSession() {
    const savedUserId = sessionStorage.getItem('currentUserId');
    const savedUsername = sessionStorage.getItem('currentUsername');
    const savedToken = sessionStorage.getItem('currentUserToken');
    
    if (savedUserId && savedUsername && savedToken) {
        currentUserId = savedUserId;
        currentUsername = savedUsername;
        currentUserToken = savedToken;
        
        // Update UI
        currentUser.textContent = currentUsername;
        
        // Show password manager UI
        authContainer.style.display = 'none';
        passwordManager.style.display = 'block';
        
        // Load user's password entries
        loadPasswordEntries();
    }
}

// Initialize on page load
checkSession();

// Add auto-logout timer for security
let inactivityTimer;
const INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes

function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    if (currentUserId) {
        inactivityTimer = setTimeout(() => {
            alert('You have been logged out due to inactivity');
            logoutUser();
        }, INACTIVITY_TIMEOUT);
    }
}

// Reset timer on user activity
['click', 'keypress', 'mousemove', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetInactivityTimer);
});

// Initialize inactivity timer
resetInactivityTimer();
