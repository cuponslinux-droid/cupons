# Instruções de Instalação - Chat em Tempo Real por Feedback

## 📋 Visão Geral

O sistema de chat foi atualizado para suportar **múltiplos chats independentes**, onde cada feedback tem seu próprio histórico de mensagens. Agora o chat é bidirecional (usuário ↔ admin) com notificações em tempo real via Socket.IO.

## 🔧 1. Executar Scripts SQL (EM ORDEM)

Execute os comandos no MySQL na ordem especificada:

### Script 1: Criar estrutura base (se ainda não executado)
```bash
mysql -u root -p linux < scripts/01-create-database.sql
```

### Script 2: Popular cupons iniciais (se ainda não executado)
```bash
mysql -u root -p linux < scripts/02-seed-coupons.sql
```

### Script 3: Atualizar cupons premium (se ainda não executado)
```bash
mysql -u root -p linux < scripts/03-update-premium-coupons.sql
```

### Script 4: **NOVO** - Migração para Chat em Tempo Real
```bash
mysql -u root -p linux < scripts/05-chat-realtime-migration.sql
```

**⚠️ IMPORTANTE:** O script `05-chat-realtime-migration.sql`:
- Remove a tabela `conversas` (não será mais usada)
- Recria a tabela `mensagens_chat` com a estrutura correta
- Adiciona Foreign Key entre `mensagens_chat.feedback_id` e `feedback.id`
- Adiciona índices para melhor performance

### Estrutura Final das Tabelas

#### Tabela `feedback`
```sql
CREATE TABLE feedback (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  telefone VARCHAR(50),
  assunto VARCHAR(255) NOT NULL,
  mensagem TEXT NOT NULL,
  status ENUM('novo', 'lido', 'respondido', 'resolvido') DEFAULT 'novo',
  criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

#### Tabela `mensagens_chat`
```sql
CREATE TABLE mensagens_chat (
  id INT AUTO_INCREMENT PRIMARY KEY,
  feedback_id INT NOT NULL,
  remetente ENUM('usuario', 'admin') NOT NULL,
  mensagem TEXT NOT NULL,
  data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  lida BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (feedback_id) REFERENCES feedback(id) ON DELETE CASCADE
);
```

## 🚀 2. Arquivos Atualizados

Os seguintes arquivos foram modificados/criados:

### ✅ Criados
- `scripts/05-chat-realtime-migration.sql` - Script de migração do banco

### ✅ Atualizados
- `server.js` - Suporte a salas dinâmicas (feedback_X)
- `lib/auth.ts` - Adiciona campo `papel` ao retorno de `getCurrentUser()`
- `app/api/chat/feedback/[feedbackId]/route.ts` - Já existia e está correto
- `components/chat.tsx` - Atualizado para usar feedbackId dinâmico
- `components/chat-window-realtime.tsx` - Já usa feedbackId corretamente
- `components/feedback-manager.tsx` - Já integra o chat corretamente

## 🎯 3. Como Funciona

### Fluxo do Chat

1. **Usuário envia feedback** pelo formulário de contato
   - Cria um registro na tabela `feedback`
   - Status inicial: `novo`

2. **Admin visualiza no painel** (`/admin/feedback`)
   - Pode clicar em "Responder via Chat" em qualquer feedback
   - Abre janela de chat conectada àquele `feedback.id`

3. **Troca de mensagens em tempo real**
   - Admin e usuário entram na sala `feedback_${feedbackId}` via Socket.IO
   - Mensagens são salvas no MySQL com `feedback_id`, `remetente` e `mensagem`
   - Ambos recebem mensagens instantaneamente via Socket.IO

4. **Notificações visuais**
   - Quando o chat está fechado e chega mensagem nova: mostra 🔴
   - Status do feedback muda automaticamente:
     - `novo` → `lido` (quando admin abre o chat)
     - `lido` → `respondido` (quando admin envia mensagem)

### Salas Socket.IO

Cada feedback tem sua própria sala:
- Sala: `feedback_${feedbackId}`
- Exemplo: `feedback_1`, `feedback_42`, etc.
- Admin entra na sala quando abre o chat daquele feedback
- Usuário pode entrar na sala usando o componente `<Chat feedbackId={1} />`

## 📱 4. Como Usar no Frontend

### Para Admin (já integrado)
```tsx
// Em /admin/feedback - FeedbackManager já está configurado
<ChatWindowRealtime
  feedbackId={chatAberto.feedbackId}
  titulo={chatAberto.titulo}
  onClose={() => setChatAberto(null)}
  onFinalizar={() => finalizarConversa(chatAberto.feedbackId)}
/>
```

### Para Usuário (integrar onde necessário)
```tsx
import Chat from "@/components/chat"

// Em uma página do usuário (exemplo: /painel)
<Chat feedbackId={meuFeedbackId} />
```

**Nota:** O usuário precisa saber qual é o `feedbackId` dele. Você pode:
- Buscar na API: `GET /api/feedback?email=${user.email}`
- Criar endpoint específico: `GET /api/user/feedback`
- Passar como prop após envio do formulário

## 🔐 5. Segurança

### Autenticação Obrigatória
Todas as rotas de chat exigem autenticação:
```typescript
const user = await getCurrentUser()
if (!user) return NextResponse.json({ error: "Não autorizado" }, { status: 401 })
```

### Identificação Automática
O remetente é identificado automaticamente pelo papel do usuário:
```typescript
const remetente = user.papel === "admin" ? "admin" : "usuario"
```

### Integridade de Dados
Foreign Key garante que mensagens só existem para feedbacks válidos:
```sql
FOREIGN KEY (feedback_id) REFERENCES feedback(id) ON DELETE CASCADE
```

## 🧪 6. Testar o Sistema

### Passo 1: Criar um Feedback
1. Acesse `/contato`
2. Preencha o formulário e envie
3. Anote o ID do feedback criado

### Passo 2: Admin Responde
1. Faça login como admin
2. Acesse `/admin/feedback`
3. Clique em "Responder via Chat" no feedback criado
4. Envie uma mensagem

### Passo 3: Verificar Tempo Real
1. Abra duas abas do navegador
2. Tab 1: Admin no chat (`/admin/feedback`)
3. Tab 2: Usuário com componente `<Chat feedbackId={X} />`
4. Envie mensagens em ambas as abas
5. Verifique que aparecem instantaneamente sem reload

### Passo 4: Verificar Notificações
1. Feche a janela do chat
2. Peça para alguém enviar uma mensagem
3. Verifique se aparece o badge vermelho 🔴
4. Abra o chat e veja que o badge desaparece

## 📊 7. Logs e Debug

### Console do Servidor (terminal)
```
✅ Cliente conectado: abc123
📥 abc123 entrou na sala: feedback_42
📡 Mensagem emitida na sala feedback_42
📤 abc123 saiu da sala: feedback_42
❌ Cliente desconectado: abc123
```

### Console do Browser (DevTools)
```
✅ Socket.IO conectado para feedback 42
📨 Nova mensagem recebida no admin: {...}
```

### Verificar no MySQL
```sql
-- Ver todos os feedbacks
SELECT id, nome, email, assunto, status FROM feedback;

-- Ver mensagens de um feedback específico
SELECT * FROM mensagens_chat WHERE feedback_id = 42 ORDER BY data ASC;

-- Contar mensagens por feedback
SELECT feedback_id, COUNT(*) as total
FROM mensagens_chat
GROUP BY feedback_id;
```

## ⚠️ 8. Troubleshooting

### Problema: Mensagens não aparecem em tempo real
**Solução:**
1. Verifique se o Socket.IO está rodando: `console.log(global.io)`
2. Confirme que entrou na sala: verifique logs do servidor
3. Teste a conexão: `socket.connected` deve ser `true`

### Problema: Erro "feedback_id não pode ser NULL"
**Solução:**
1. Execute o script `05-chat-realtime-migration.sql`
2. Confirme que a coluna `feedback_id` existe na tabela

### Problema: Foreign Key error
**Solução:**
1. Certifique-se que o feedback existe: `SELECT * FROM feedback WHERE id = X`
2. Se não existir, crie o feedback antes de enviar mensagens

### Problema: Mensagens duplicadas
**Solução:**
Verificar se está criando múltiplos sockets. Use cleanup no useEffect:
```typescript
return () => {
  socketInstance.emit("leave_feedback", feedbackId)
  socketInstance.disconnect()
}
```

## 🎓 9. Próximos Passos Sugeridos

1. **Implementar permissões avançadas**
   - Usuário só vê seus próprios feedbacks
   - Admin vê todos

2. **Adicionar indicador de digitação**
   - Mostrar "Admin está digitando..." ou vice-versa
   - Usar evento Socket.IO `typing`

3. **Notificações push**
   - Integrar com Push API do browser
   - Notificar mesmo quando página está fechada

4. **Upload de arquivos**
   - Permitir enviar imagens/documentos no chat
   - Armazenar URLs no banco

5. **Histórico de conversas**
   - Permitir buscar mensagens antigas
   - Filtrar por data/remetente

## 📞 10. Suporte

Se encontrar problemas:
1. Verifique os logs do servidor e do browser
2. Confirme que o banco foi migrado corretamente
3. Teste cada componente isoladamente
4. Revise este documento passo a passo

---

**Versão:** 1.0
**Data:** 26/10/2025
**Autor:** Sistema Linux Cupons
