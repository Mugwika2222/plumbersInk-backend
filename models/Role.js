import { DataTypes } from 'sequelize';

const Role = (sequelize, Sequelize) => {
    const Role = sequelize.define('Role', {
      id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
      },
      role: {
        type: DataTypes.ENUM('admin', 'plumber', 'client'),
        allowNull: false,
      },

    });
    return Role;
};
export default Role;