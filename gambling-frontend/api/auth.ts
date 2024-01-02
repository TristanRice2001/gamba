import { AuthRequest, AuthResponse, LoginRequest } from "../types/api/auth";
import { baseInstance } from "./base";
import { LOGIN, REGISTER } from "./endpoints";

export const apiLogin = (request: LoginRequest) =>
  baseInstance.post<AuthResponse>(
    process.env.NEXT_PUBLIC_API_URL + LOGIN,
    request
  );

export const apiRegister = (request: AuthRequest) =>
  baseInstance.post<AuthResponse>(
    process.env.NEXT_PUBLIC_API_URL + REGISTER,
    request
  );
