import express from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import User from '../models/User.js';
import Verificacao from '../models/Verificacao.js';
import { gerarToken, getSigningSecret, autenticarObrigatorio } from '../middleware/auth.js';
import { textField, emailField, passwordField, currentPasswordField, httpUrl, validate, databaseError } from '../middleware/validation.js';
import { createPasswordRecoveryRouter } from './password-recovery.js';
const router = express.Router();
// Precomputed at bcrypt cost 12 so missing/inactive accounts still perform one
// password comparison. A match against this value never authenticates a user.
const DUMMY_PASSWORD_HASH = '$2b$12$.LGYpVX/rMGzGgCdEDKc4.9cCiZ929Sa9F3Q.lMUrb6bqtciWbyau';
router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
router.use(createPasswordRecoveryRouter());
const registerSchema = z.object({ nome: textField().min(2), email: emailField, senha: passwordField, cidade: textField().optional() }).strict();
const loginSchema = z.object({ email: emailField, senha: currentPasswordField }).strict();
const profileSchema = z.object({ nome: textField().min(2).optional(), cidade: textField().optional(), fotoPerfil: z.union([z.literal(''), httpUrl.refine(value => value.length <= 500)]).optional() }).strict();
const passwordSchema = z.object({ novaSenha: passwordField, confirmarSenha: passwordField }).strict()
  .refine(body => body.novaSenha === body.confirmarSenha, 'As senhas não coincidem.');
export function dadosPublicos(user, totalVerificacoes) {
  return { id: user._id, _id: user._id, nome: user.nome, email: user.email, role: user.role, cidade: user.cidade, fotoPerfil: user.fotoPerfil || '', createdAt: user.createdAt, totalVerificacoes };
}
function authUnavailable(res, error) {
  if (error?.status === 503) return res.status(503).json({ sucesso: false, erro: 'Autenticação indisponível.' });
  return databaseError(res, error);
}
router.post('/registrar', async (req, res) => {
  const body = validate(registerSchema, req.body, res); if (!body) return;
  try {
    getSigningSecret();
    if (await User.exists({ email: body.email })) return res.status(409).json({ sucesso: false, erro: 'Já existe uma conta com esse e-mail.' });
    const user = await User.create({ ...body, senha: await bcrypt.hash(body.senha, 12), role: 'user' });
    return res.status(201).json({ sucesso: true, token: gerarToken(user._id, user.tokenVersion || 0), usuario: dadosPublicos(user) });
  } catch (error) { return authUnavailable(res, error); }
});
router.post('/entrar', async (req, res) => {
  const body = validate(loginSchema, req.body, res); if (!body) return;
  try {
    getSigningSecret();
    const user = await User.findOne({ email: body.email }).select('+senha');
    const hasActivePassword = Boolean(user?.ativo && typeof user.senha === 'string' && user.senha);
    const passwordMatches = await bcrypt.compare(body.senha, hasActivePassword ? user.senha : DUMMY_PASSWORD_HASH);
    if (!hasActivePassword || !passwordMatches) return res.status(401).json({ sucesso: false, erro: 'E-mail ou senha incorretos.' });
    return res.json({ sucesso: true, token: gerarToken(user._id, user.tokenVersion || 0), usuario: dadosPublicos(user) });
  } catch (error) { return authUnavailable(res, error); }
});
async function profile(req, res) {
  try {
    const count = await Verificacao.countDocuments({ userId: req.user._id });
    return res.json({ sucesso: true, usuario: dadosPublicos(req.user, count) });
  } catch (error) { return databaseError(res, error, 'Não foi possível carregar o perfil.'); }
}
router.get('/me', autenticarObrigatorio, profile);
router.get('/perfil', autenticarObrigatorio, profile);
router.patch('/perfil', autenticarObrigatorio, async (req, res) => {
  const body = validate(profileSchema, req.body, res); if (!body) return;
  try {
    const updates = body;
    if (!Object.keys(updates).length) return res.status(400).json({ sucesso: false, erro: 'Informe ao menos um campo para atualizar.' });
    const user = await User.findByIdAndUpdate(req.user._id, { $set: updates }, { new: true, runValidators: true });
    if (!user) return res.status(404).json({ sucesso: false, erro: 'Usuário não encontrado.' });
    const count = await Verificacao.countDocuments({ userId: user._id });
    return res.json({ sucesso: true, mensagem: 'Perfil atualizado com sucesso.', usuario: dadosPublicos(user, count) });
  } catch (error) { return databaseError(res, error, 'Não foi possível atualizar o perfil.'); }
});
router.patch('/senha', autenticarObrigatorio, async (req, res) => {
  const body = validate(passwordSchema, req.body, res); if (!body) return;
  try {
    const version = req.user.tokenVersion || 0;
    const senha = await bcrypt.hash(body.novaSenha, 12);
    // Update the password and revoke older sessions/reset links together. Checking
    // the version again prevents an in-flight revoked session from overwriting it.
    const user = await User.findOneAndUpdate({
      _id: req.user._id, ativo: true,
      ...(version ? { tokenVersion: version } : { $or: [{ tokenVersion: 0 }, { tokenVersion: { $exists: false } }] })
    }, {
      $set: { senha },
      $unset: { resetPasswordTokenHash: '', resetPasswordExpiresAt: '', resetPasswordRequestedAt: '' },
      $inc: { tokenVersion: 1 }
    }, { new: true, runValidators: true });
    if (!user) return res.status(401).json({ sucesso: false, erro: 'Sua sessão expirou. Entre novamente para continuar.' });
    return res.json({ sucesso: true, mensagem: 'Senha alterada com sucesso.', token: gerarToken(user._id, user.tokenVersion) });
  } catch (error) { return databaseError(res, error, 'Não foi possível alterar a senha.'); }
});
export default router;
