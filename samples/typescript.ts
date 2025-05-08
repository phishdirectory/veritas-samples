import * as crypto from 'crypto';

/**
 * TypeScript client for the Veritas authentication API
 */
export class VeritasClient {
  private apiUrl: string;
  private apiKey: string;
  private hashKey: string;

  /**
   * Initialize the Veritas client
   * @param apiUrl Base URL for the Veritas API
   * @param apiKey Your service API key
   * @param hashKey Your service hash key for encrypting data
   */
  constructor(apiUrl: string, apiKey: string, hashKey: string) {
    this.apiUrl = apiUrl.endsWith('/') ? apiUrl.slice(0, -1) : apiUrl;
    this.apiKey = apiKey;
    this.hashKey = hashKey;
  }

  /**
   * Authenticate a user with email and password
   * @param email User's email
   * @param password User's password
   * @returns Promise resolving to authentication result
   */
  async authenticate(email: string, password: string): Promise<AuthResponse> {
    const credentials = { email, password };
    const hashedData = this.hashData(credentials);

    return this.post<AuthResponse>('/auth/authenticate', { credentials: hashedData });
  }

  /**
   * Get user information by PD_ID
   * @param pdId User's PD_ID
   * @returns Promise resolving to user information
   */
  async getUser(pdId: string): Promise<UserResponse> {
    return this.get<UserResponse>(`/users/${pdId}`);
  }

  /**
   * Get user information by email
   * @param email User's email
   * @returns Promise resolving to user information
   */
  async getUserByEmail(email: string): Promise<UserResponse> {
    return this.get<UserResponse>(`/users/by_email?email=${encodeURIComponent(email)}`);
  }

  /**
   * Create a new user
   * @param userData User data including first_name, last_name, email, password, password_confirmation
   * @returns Promise resolving to new user information
   */
  async createUser(userData: NewUserData): Promise<CreateUserResponse> {
    const hashedData = this.hashData(userData);
    return this.post<CreateUserResponse>('/users', { hashed_data: hashedData });
  }

  /**
   * Make a GET request to the API
   * @param path API endpoint path
   * @returns Promise resolving to response data
   */
  private async get<T>(path: string): Promise<T> {
    const response = await fetch(`${this.apiUrl}/api/v1${path}`, {
      method: 'GET',
      headers: {
        'X-Api-Key': this.apiKey,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  /**
   * Make a POST request to the API
   * @param path API endpoint path
   * @param data Request data
   * @returns Promise resolving to response data
   */
  private async post<T>(path: string, data: any): Promise<T> {
    const response = await fetch(`${this.apiUrl}/api/v1${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Api-Key': this.apiKey,
        'Accept': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  /**
   * Hash data using the service's hash_key
   * @param data Data to encrypt
   * @returns Base64 encoded encrypted data
   */
  private hashData(data: any): string {
    // Convert data to JSON string
    const jsonData = JSON.stringify(data);

    // Create key and iv from the hash_key
    const key = crypto.createHash('sha256').update(this.hashKey).digest().slice(0, 32);
    const iv = Buffer.from(this.hashKey.slice(0, 16).padEnd(16, '0'));

    // Encrypt the data
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(jsonData, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    return encrypted;
  }
}

/**
 * Authentication response type
 */
export interface AuthResponse {
  authenticated: boolean;
  pd_id?: string;
  error?: string;
}

/**
 * User response type
 */
export interface UserResponse {
  pd_id: string;
  first_name: string;
  last_name: string;
  email: string;
  permissions: {
    global_access_level: {
      name: string;
      value: number;
    };
    SERVICE_ACCESS_LEVEL?: {
      name: string;
      value: number;
    };
  };
  created_at: string;
  status: string;
  locked_at?: string;
  error?: string;
}

/**
 * New user data type
 */
export interface NewUserData {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
  password_confirmation: string;
}

/**
 * Create user response type
 */
export interface CreateUserResponse {
  success: boolean;
  pd_id?: string;
  email?: string;
  created_at?: string;
  errors?: string[];
  error?: string;
}

// Example usage
async function exampleUsage() {
  // Development URL (change to production URL in production environment)
  // Development: http://localhost:3000/api/v1/
  // Production: https://veritas.phish.directory/api/v1/
  // Note: Contact a core team member if you need production keys for authenticating with Veritas
  const isProduction = process.env.NODE_ENV === 'production';
  const API_URL = isProduction ? 'https://veritas.phish.directory' : 'http://localhost:3000';
  const API_KEY = 'your_api_key_here'; // Obtain from core team member for production
  const HASH_KEY = 'your_hash_key_here'; // Obtain from core team member for production

  const client = new VeritasClient(API_URL, API_KEY, HASH_KEY);

  try {
    // Authenticate a user
    const authResult = await client.authenticate('user@example.com', 'password123');
    console.log('Authentication result:', authResult);

    // Get user by PD_ID
    const user = await client.getUser('PDU1A2B3C4');
    console.log('User by PD_ID:', user);

    // Get user by email
    const userByEmail = await client.getUserByEmail('user@example.com');
    console.log('User by email:', userByEmail);

    // Create a new user
    const newUser = await client.createUser({
      first_name: 'John',
      last_name: 'Doe',
      email: 'john.doe@example.com',
      password: 'SecureP@ssw0rd',
      password_confirmation: 'SecureP@ssw0rd'
    });
    console.log('New user:', newUser);
  } catch (error) {
    console.error('Error:', error);
  }
}

// Uncomment to run the example
// exampleUsage();
