// Utilitários de autenticação
import { cookies } from "next/headers"
import { query } from "./db"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

export interface User {
  id: number
  name: string
  email: string
  role: "usuario" | "admin"
  papel: "usuario" | "admin"
  avatar_url?: string | null
  created_at: Date
}

export interface JWTPayload {
  id: number
  nome: string
  email: string
  papel: "usuario" | "admin"
}

export async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 10)
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash)
}

// Gerar JWT Token
export function generateToken(user: { id: number; nome: string; email: string; papel: "usuario" | "admin" }): string {
  const payload: JWTPayload = {
    id: user.id,
    nome: user.nome,
    email: user.email,
    papel: user.papel,
  }

  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: "7d",
  })
}

// Verificar JWT Token
export function verifyToken(token: string): JWTPayload | null {
  try {
    return jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload
  } catch {
    return null
  }
}

// Criar sessão (mantém compatibilidade, mas agora usa JWT)
export async function createSession(userId: number): Promise<string> {
  const users = await query("SELECT id, nome, email, papel FROM usuarios WHERE id = ?", [userId])

  if (!users || users.length === 0) {
    throw new Error("Usuário não encontrado")
  }

  const user = users[0]
  const token = generateToken({
    id: user.id,
    nome: user.nome,
    email: user.email,
    papel: user.papel,
  })

  const cookieStore = await cookies()
  cookieStore.set("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60,
  })

  return token
}

// Obter usuário da sessão (agora usa JWT)
export async function getCurrentUser(): Promise<User | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get("token")?.value

  if (!token) return null

  const payload = verifyToken(token)
  if (!payload) return null

  const users = await query(
    "SELECT id, nome, email, papel, avatar_url, criado_em FROM usuarios WHERE id = ?",
    [payload.id]
  )

  if (!users || users.length === 0) return null

  return {
    id: users[0].id,
    name: users[0].nome,
    email: users[0].email,
    role: users[0].papel,
    papel: users[0].papel,
    avatar_url: users[0].avatar_url,
    created_at: users[0].criado_em,
  }
}

// Destruir sessão
export async function destroySession(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.delete("token")
}

// Verificar se usuário é admin
export async function isAdmin(): Promise<boolean> {
  const user = await getCurrentUser()
  return user?.role === "admin"
}

// Middleware de autorização admin (corrigido)
export async function requireAdmin(): Promise<User> {
  try {
    const user = await getCurrentUser()

    if (!user) {
      throw new Error("Usuário não autenticado. Faça login para continuar.")
    }

    if (user.role !== "admin") {
      throw new Error("Acesso negado: apenas administradores podem acessar esta rota.")
    }

    return user
  } catch (error: any) {
    // Garante que nunca retorna undefined
    const message =
      error?.message || "Erro de autenticação ou permissão. Acesso negado."
    throw new Error(message)
  }
}
