# Conversa CRM

Central SaaS multicanal para atendimento, CRM e automações. Cada empresa cria seu próprio acesso e mantém usuários, contatos, mensagens e integrações separados.

## O que está pronto

- Cadastro, login e sessão por empresa (tenant).
- Painel de atendimento, CRM, funil, indicadores e automações.
- Conexão por empresa com WhatsApp Business Cloud API, Resend e Twilio.
- Envio pela interface de WhatsApp e pela janela de nova mensagem (WhatsApp, e-mail ou SMS).
- Webhooks de entrada para WhatsApp, e-mail e SMS, convertendo mensagens em contatos e histórico no CRM.
- Credenciais dos canais criptografadas em repouso com AES-256-GCM e nunca retornadas ao navegador.
- Verificação de assinatura dos webhooks da Meta, Twilio e Resend quando as variáveis/configurações de produção estão preenchidas.
- Área de administrador da plataforma para visualizar, suspender e reativar empresas vendidas.

## Executar localmente

Requer Node.js 20 ou superior.

```powershell
$env:APP_SECRET = 'gere-uma-chave-longa-e-aleatoria'
$env:APP_ENCRYPTION_KEY = 'gere-outra-chave-longa-e-aleatoria'
$env:PLATFORM_ADMIN_EMAIL = 'admin@suaempresa.com'
$env:PLATFORM_ADMIN_PASSWORD = 'uma-senha-forte-com-8-ou-mais-caracteres'
$env:PLATFORM_ADMIN_NAME = 'Seu nome'
node server.js
```

Abra `http://localhost:3000`, crie a primeira conta e entre na área **Canais** para configurar cada integração. Os dados locais são criados em `data/db.json`; esse diretório está excluído do Git por conter dados de clientes e configurações criptografadas.

## Publicação e variáveis obrigatórias

Para receber webhooks em produção, publique a aplicação atrás de HTTPS e configure:

| Variável | Uso |
| --- | --- |
| `APP_SECRET` | Segredo de sessão. Deve ser longo, exclusivo e privado. |
| `APP_ENCRYPTION_KEY` | Chave para criptografar tokens de cada empresa. Não a altere depois de cadastrar canais. |
| `PUBLIC_URL` | URL pública HTTPS, sem barra no final. Necessária para validar webhooks da Twilio. |
| `META_APP_SECRET` | App Secret da aplicação Meta que atende os números de WhatsApp. Necessária para validar a assinatura dos webhooks. |
| `PLATFORM_ADMIN_EMAIL` | E-mail da sua conta mestre. A conta é criada na primeira inicialização com esses dados. |
| `PLATFORM_ADMIN_PASSWORD` | Senha inicial da conta mestre; use ao menos 8 caracteres e remova a variável depois da criação, se desejar. |
| `PLATFORM_ADMIN_NAME` | Nome exibido no painel mestre. |
| `PORT` | Porta HTTP da aplicação; padrão `3000`. |

Nunca coloque nenhuma dessas chaves no HTML, no Git ou em uma conta de cliente.

## Conta ADM e inadimplência

Defina as três variáveis `PLATFORM_ADMIN_*` acima antes de iniciar a plataforma pela primeira vez. Ao entrar com esse e-mail, o Conversa abre a área exclusiva `admin.html`, que exibe todas as empresas cadastradas, responsável, canais conectados, contatos, volume de mensagens e situação.

O botão **Suspender** encerra imediatamente as sessões dos usuários daquela empresa e bloqueia novos acessos, sem apagar dados. Use-o em inadimplência. O botão passa a ser **Reativar** assim que o pagamento for regularizado. Cada alteração fica registrada em “Últimas ações”.

## Conectar WhatsApp Business

1. Crie/registre a aplicação no Meta for Developers e associe o produto WhatsApp.
2. Gere um token permanente com acesso à conta do cliente e obtenha o **Phone Number ID** e o **WhatsApp Business Account ID**.
3. No Conversa, abra **Canais → Conectar WhatsApp** e salve esses dados.
4. No Meta, cadastre `https://SEU-DOMINIO/webhooks/whatsapp` como Callback URL e use o mesmo token de verificação informado no Conversa.
5. Assine o evento `messages` no webhook. A partir daí, novas mensagens criam/atualizam contatos e entram na central.

O envio usa a Cloud API oficial. Respeite a janela de atendimento de 24 horas e use templates aprovados para iniciar conversas fora da janela.

## Conectar e-mail e SMS

- **E-mail (Resend):** verifique o domínio, use um remetente autorizado e crie um webhook do evento `email.received` em `https://SEU-DOMINIO/webhooks/email`. Informe também o endereço de entrada e o segredo `whsec_...` retornado pela Resend.
- **SMS (Twilio):** informe o número remetente, Account SID e Auth Token. No número ou Messaging Service da Twilio, configure `https://SEU-DOMINIO/webhooks/sms` como webhook de mensagem recebida (POST).

## Antes de vender em escala

Esta entrega é uma base funcional para piloto/primeiros clientes, com armazenamento local em arquivo para simplicidade. Antes de operação com múltiplas instâncias ou volume relevante, migre `data/db.json` para um banco gerenciado com backup, implemente recuperação de senha/convites por e-mail, logs/auditoria, limites por plano, políticas LGPD, monitoramento e filas para reenvio seguro de webhooks.
