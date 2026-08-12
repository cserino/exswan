import { 
  startRegistration, 
  startAuthentication,
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill
} from '@simplewebauthn/browser';

// WebAuthn utilities
const WebAuthnClient = {
  async register(email) {
    try {
      // Get registration options from server
      const response = await fetch('/api/webauthn/register/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
        },
        body: JSON.stringify({ email })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to start registration');
      }

      const options = await response.json();

      // Start WebAuthn registration
      const credential = await startRegistration({optionsJSON: options});

      // Send credential to server for verification
      const verifyResponse = await fetch('/api/webauthn/register/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
        },
        body: JSON.stringify(credential)
      });

      if (!verifyResponse.ok) {
        const error = await verifyResponse.json();
        throw new Error(error.error || 'Failed to complete registration');
      }

      const result = await verifyResponse.json();
      return result;
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  },

  async authenticate(email = null) {
    try {
      // Get authentication options from server
      const body = email ? JSON.stringify({ email }) : JSON.stringify({});
      const response = await fetch('/api/webauthn/authenticate/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
        },
        body
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to start authentication');
      }

      const options = await response.json();

      // Start WebAuthn authentication
      const credential = await startAuthentication({optionsJSON: options});

      // Send credential to server for verification
      const verifyResponse = await fetch('/api/webauthn/authenticate/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
        },
        body: JSON.stringify(credential)
      });

      if (!verifyResponse.ok) {
        const error = await verifyResponse.json();
        throw new Error(error.error || 'Failed to complete authentication');
      }

      const result = await verifyResponse.json();
      return result;
    } catch (error) {
      console.error('Authentication error:', error);
      throw error;
    }
  },

  checkSupport() {
    return {
      webauthn: browserSupportsWebAuthn(),
      autofill: browserSupportsWebAuthnAutofill()
    };
  }
};

// UI utilities
const UI = {
  showStatus(message, isError = false) {
    const statusDiv = document.getElementById('webauthn-status');
    const errorDiv = document.getElementById('webauthn-error');
    const messageEl = document.getElementById('webauthn-message');
    const errorMessageEl = document.getElementById('webauthn-error-message');

    if (isError) {
      statusDiv?.classList.add('hidden');
      errorDiv?.classList.remove('hidden');
      if (errorMessageEl) errorMessageEl.textContent = message;
    } else {
      errorDiv?.classList.add('hidden');
      statusDiv?.classList.remove('hidden');
      if (messageEl) messageEl.textContent = message;
    }
  },

  hideStatus() {
    const statusDiv = document.getElementById('webauthn-status');
    const errorDiv = document.getElementById('webauthn-error');
    statusDiv?.classList.add('hidden');
    errorDiv?.classList.add('hidden');
  },

  disableButton(buttonId, disabled = true) {
    const button = document.getElementById(buttonId);
    if (button) {
      button.disabled = disabled;
      if (disabled) {
        button.classList.add('opacity-50', 'cursor-not-allowed');
      } else {
        button.classList.remove('opacity-50', 'cursor-not-allowed');
      }
    }
  }
};

// Event handlers
function setupRegistrationHandlers() {
  const registerButton = document.getElementById('register-passkey');
  const addPasskeyButton = document.getElementById('add-passkey');

  // Handle passkey registration on registration page
  registerButton?.addEventListener('click', async (e) => {
    e.preventDefault();
    
    const email = e.target.dataset.email || window.userEmail;
    if (!email) {
      UI.showStatus('Email not found', true);
      return;
    }

    if (!WebAuthnClient.checkSupport().webauthn) {
      UI.showStatus('WebAuthn is not supported in this browser', true);
      return;
    }

    UI.disableButton('register-passkey');
    UI.showStatus('Setting up your passkey...');

    try {
      const result = await WebAuthnClient.register(email);
      
      if (result.success && result.redirect) {
        UI.showStatus('Passkey created successfully! Redirecting...');
        setTimeout(() => {
          window.location.href = result.redirect;
        }, 1000);
      }
    } catch (error) {
      UI.showStatus(error.message, true);
    } finally {
      UI.disableButton('register-passkey', false);
    }
  });

  // Handle adding additional passkey on dashboard
  addPasskeyButton?.addEventListener('click', async (e) => {
    e.preventDefault();
    
    const email = e.target.dataset.email || window.userEmail;
    if (!email) {
      UI.showStatus('Email not found', true);
      return;
    }

    if (!WebAuthnClient.checkSupport().webauthn) {
      UI.showStatus('WebAuthn is not supported in this browser', true);
      return;
    }

    UI.disableButton('add-passkey');
    UI.showStatus('Setting up your passkey...');

    try {
      const result = await WebAuthnClient.register(email);
      
      if (result.success) {
        UI.showStatus('Passkey added successfully! Reloading...');
        setTimeout(() => {
          window.location.reload();
        }, 1000);
      }
    } catch (error) {
      UI.showStatus(error.message, true);
    } finally {
      UI.disableButton('add-passkey', false);
    }
  });
}

function setupAuthenticationHandlers() {
  const signinButton = document.getElementById('signin-passkey');
  const emailForm = document.getElementById('email-signin-form');

  // Handle usernameless authentication
  signinButton?.addEventListener('click', async (e) => {
    e.preventDefault();

    if (!WebAuthnClient.checkSupport().webauthn) {
      UI.showStatus('WebAuthn is not supported in this browser', true);
      return;
    }

    UI.disableButton('signin-passkey');
    UI.showStatus('Please use your passkey to sign in...');

    try {
      const result = await WebAuthnClient.authenticate();
      
      if (result.success && result.redirect) {
        UI.showStatus('Signed in successfully! Redirecting...');
        setTimeout(() => {
          window.location.href = result.redirect;
        }, 1000);
      }
    } catch (error) {
      UI.showStatus(error.message, true);
    } finally {
      UI.disableButton('signin-passkey', false);
    }
  });

  // Handle email-based authentication
  emailForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const emailInput = document.getElementById('email');
    const email = emailInput?.value;

    if (!email) {
      UI.showStatus('Please enter your email address', true);
      return;
    }

    if (!WebAuthnClient.checkSupport().webauthn) {
      UI.showStatus('WebAuthn is not supported in this browser', true);
      return;
    }

    const submitButton = emailForm.querySelector('button[type="submit"]');
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.classList.add('opacity-50');
    }

    UI.showStatus('Please use your passkey to sign in...');

    try {
      const result = await WebAuthnClient.authenticate(email);
      
      if (result.success && result.redirect) {
        UI.showStatus('Signed in successfully! Redirecting...');
        setTimeout(() => {
          window.location.href = result.redirect;
        }, 1000);
      }
    } catch (error) {
      UI.showStatus(error.message, true);
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.classList.remove('opacity-50');
      }
    }
  });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  setupRegistrationHandlers();
  setupAuthenticationHandlers();

  // Check WebAuthn support and show warning if not supported
  const support = WebAuthnClient.checkSupport();
  if (!support.webauthn) {
    console.warn('WebAuthn is not supported in this browser');
  }
});

// Export for global access if needed
window.WebAuthnClient = WebAuthnClient;
