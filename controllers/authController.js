import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import db from '../models/index.js';

const { User, Role, UserRole } = db;

const signup = async (req, res, next) => {
  const { username, email, password, } = req.body;

  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists. Please use a different email.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hash });

    const clientRole = await Role.findOne({ where: { role: 'client' } });
    if (clientRole) {
      await user.addRole(clientRole);
    }

    const token = jwt.sign({ id: user.id }, 'secret_key', { expiresIn: '1hr' });
    res.json({ token });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      res.status(401).json({ message: 'This email is not registered' });
      return;
    }

    const result = await bcrypt.compare(password, user.password);
    if (result) {
      const userRoles = await UserRole.findByPk(user.id);
     // const roleIds = userRoles.map(userRole => userRole.role_id);

      const token = jwt.sign({ id: user.id }, 'secret_jwt', { expiresIn: '1hr' });
      res.json({ token, user,userRoles });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    next(error);
  }
};

const verifyEmail = async (req, res, next) => {
  try {
    const token = req.params.token;

    // Verify the token using the secret key
    jwt.verify(token, process.env.SECRET_KEY, async (err, decoded) => {
      if (err) {
        return res.status(401).send('Token verification failed'); // Token verification failed
      }

      // Check if the token exists in the database
      const user = await User.findOne({ where: { verificationToken: token } });

      if (!user) {
        return res.status(404).send('User not found'); // Token not found in the database
      }

      if (user.verified) {
        return res.status(400).send('Email already verified'); // Email already verified
      }

      // Nullify the token (you can also remove it from the user record if needed)
      user.verificationToken = null;

      // Mark the user as verified
      user.verified = true;

      // Mark the user status as active
      user.status = 'active';

      await user.save();

      // You can customize the response based on your needs
      return res.status(200).send('Email verified successfully');
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).send('Email verification error'); // Server error
  }
};


const changePassword = async (req, res, next) => {
  const { currentPassword, newPassword, user_id } = req.body;

  try {
    // Find the user by ID
    const user = await User.findByPk(user_id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify that the current password matches the one stored in the database
    const passwordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    // Update the user's password with the new password
    const hash = await bcrypt.hash(newPassword, 10);
    user.password = hash;

    await user.save();

    return res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Password change error:', error);
    next(error);
  }
};


const deactivateAccount = async (req, res, next) => {
  const { user_id } = req.body;

  try {
    // Find the user by ID
    const user = await User.findByPk(user_id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update the user's status to 'deactivated'
    user.status = 'deactivated';

    await user.save();

    return res.status(200).json({ message: 'Account deactivated successfully' });
  } catch (error) {
    console.error('Account deactivation error:', error);
    next(error);
  }
};


const reactivateAccount = async (req, res, next) => {
  const { user_id } = req.body;

  try {
    // Find the user by ID
    const user = await User.findByPk(user_id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update the user's status to 'active'
    user.status = 'active';

    await user.save();

    return res.status(200).json({ message: 'Account reactivated successfully' });
  } catch (error) {
    console.error('Account reactivation error:', error);
    next(error);
  }
};


const forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email: email } });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a new JWT token
    const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '1hr' });

    // Save the token in the database
    await user.update({ passwordResetToken: token });

    // Include the token and user's firstName in the response JSON
    res.status(200).json({
      message: 'Password reset email sent successfully',
      token,
      firstName: user.firstName, // Include the user's firstName
      email: user.email, // Include the user's email
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    next(error);
  }
};


const verifyPasswordResetToken = async (req, res, next) => {
  try {
    const token = req.params.token;

    // Verify the token using the secret key
    jwt.verify(token, process.env.SECRET_KEY, async (err, decoded) => {
      if (err) {
        return res.status(401).send('Token verification failed'); // Token verification failed
      }

      // Check if the token exists in the database
      const user = await User.findOne({ where: { passwordResetToken: token } });

      if (!user) {
        return res.status(404).send('User not found'); // Token not found in the database
      }

      // Nullify the token (you can also remove it from the user record if needed)
      user.passwordResetToken = null;

      await user.save();

      // Respond with a JSON object including the user's email
      res.status(200).json({
        message: 'Token verified successfully',
        email: user.email, // Include the user's email
      });
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).send('Token verification error'); // Server error
  }
};


const resetPassword = async (req, res, next) => {
  const { newPassword, email } = req.body;

  try {
    // Check if the email exists in the database
    const user = await User.findOne({ where: { email: email } });

    if (!user) {
      return res.status(404).send('User not found'); // Token not found in the database
    }

    // Update the user's password with the new password
    const hash = await bcrypt.hash(newPassword, 10);
    user.password = hash;

    await user.save();

    // You can customize the response based on your needs
    return res.status(200).send('Password reset successfully');
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).send('Password reset error'); // Server error
  }
}
 

export { signup, login, verifyEmail, changePassword, deactivateAccount, reactivateAccount, forgotPassword, verifyPasswordResetToken, resetPassword };