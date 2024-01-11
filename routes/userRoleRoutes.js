import express from 'express';

import { createUserRole,getAllUserRoles, getUserRoleById, updateUserRoleById, deleteUserRoleById } from '../controllers/userRoleController.js';

const router = express.Router();

router.get('/user-role',getAllUserRoles );

router.get('/user-role/:id',getUserRoleById );

router.post('/user-role', createUserRole);

router.patch('/user-role/:id', updateUserRoleById);

router.delete('/user-role/:id',deleteUserRoleById );

export default router;