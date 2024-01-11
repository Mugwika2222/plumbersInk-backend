import { Sequelize } from 'sequelize';

import sequelize from '../config/db.js';

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

import User from './User.js';
db.User = User(sequelize, Sequelize);

import Role from './Role.js';
db.Role = Role(sequelize, Sequelize);

import UserRole from "../models/UserRole.js";
db.UserRole = UserRole(sequelize, Sequelize);





//Role & User has Many-To-Many Relationship
db.Role.belongsToMany(db.User, {
  through: "user_roles",
  foreignKey: "role_id",
  otherKey: "user_id"
});

db.User.belongsToMany(db.Role, {
  through: "user_roles",
  foreignKey: "user_id",
  otherKey: "role_id"
});


export default db;