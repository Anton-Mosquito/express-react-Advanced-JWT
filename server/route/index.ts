import { Router } from 'express';
import userController from '../controllers/user-controller.js';
import validateMiddleware from '../middleware/validate-middleware.js';
import { registrationSchema, loginSchema } from '../dtos/auth.schema.js';
import authMiddleware from '../middleware/auth-middleware.js';

const router = Router();

router.post(
  '/registration',
  validateMiddleware(registrationSchema),
  userController.registration,
);
router.post('/login', validateMiddleware(loginSchema), userController.login);
router.post('/logout', userController.logout);
router.get('/activate/:link', userController.activate);
router.get('/refresh', userController.refresh);
router.get('/users', authMiddleware, userController.getUser);

export default router;
