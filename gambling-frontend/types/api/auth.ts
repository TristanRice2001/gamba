export type AuthRequest = {
  email: string;
  username: string;
  password: string;
  recaptchaToken: string;
};

export type AuthResponse = {
  jwtToken: string;
};

export type LoginRequest = {
  emailOrUsername: string;
  password: string;
  recaptchaToken: string;
};
