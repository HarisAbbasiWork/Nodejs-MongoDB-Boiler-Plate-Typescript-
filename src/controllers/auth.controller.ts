import config from "config";
import { CookieOptions, NextFunction, Request, Response } from "express";
import { CreateUserInput, LoginUserInput } from "../schema/user.schema";
import {
  createUser,
  findUser,
  findUserById,
  signToken,
} from "../services/user.service";
import AppError from "../utils/appError";
import redisClient from "../utils/connectRedis";
import { signJwt, verifyJwt } from "../utils/jwt";
import otpGenerator from 'otp-generator';
import Role from '../models/role.model';
import otpModel, { Otp } from '../models/otp.model';
import userModel, { User } from '../models/user.model';
import bcrypt from 'bcryptjs';
import {
  sendEmail,
  //sendMessage
} from '../utils/communication';
import { DocumentType } from '@typegoose/typegoose';
import mongoose from 'mongoose';
const saltRounds = 10;
// Exclude this fields from the response
// Exclude this fields from the response
// Exclude this fields from the response
export const excludedFields = ["password"];

// Cookie options
const accessTokenCookieOptions: CookieOptions = {
  expires: new Date(
    Date.now() + config.get<number>("accessTokenExpiresIn") * 60 * 1000
  ),
  maxAge: config.get<number>("accessTokenExpiresIn") * 60 * 1000,
  httpOnly: true,
  sameSite: "lax",
};

const refreshTokenCookieOptions: CookieOptions = {
  expires: new Date(
    Date.now() + config.get<number>("refreshTokenExpiresIn") * 60 * 1000
  ),
  maxAge: config.get<number>("refreshTokenExpiresIn") * 60 * 1000,
  httpOnly: true,
  sameSite: "lax",
};

// Only set secure to true in production
if (process.env.NODE_ENV === "production")
  accessTokenCookieOptions.secure = true;

export const registerHandler = async (
  req: Request<{}, {}, CreateUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const { firstname, lastname, name, email, address, role } = req.body;
    const user = await createUser({
      email: email,
      password: req.body.password,
      firstname,
      lastname,
      name,
      address,
      role: new mongoose.Types.ObjectId(role) // Convert string to ObjectId
    });

    res.status(201).json({
      status: "success",
      data: {
        user,
      },
    });
  } catch (err: any) {
    if (err.code === 11000) {
      return res.status(409).json({
        status: "fail",
        message: "Email already exist",
      });
    }
    next(err);
  }
};

export const loginHandler = async (
  req: Request<{}, {}, LoginUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    // Get the user from the collection
    const user = await findUser({ email: req.body.email });

    // Check if user exist and password is correct
    if (
      !user ||
      !(await user.comparePasswords(user.password, req.body.password))
    ) {
      return next(new AppError("Invalid email or password", 401));
    }

    // Create the Access and refresh Tokens
    const { access_token, refresh_token } = await signToken(user);

    // Send Access Token in Cookie
    res.cookie("access_token", access_token, accessTokenCookieOptions);
    res.cookie("refresh_token", refresh_token, refreshTokenCookieOptions);
    res.cookie("logged_in", true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    // Send Access Token
    res.status(200).json({
      status: "success",
      access_token,
    });
  } catch (err: any) {
    console.log("err ",err)
    next(err);
  }
};

export const sendOtpHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, phoneno } = req.body;
    //Creating OTP for SMS
    var otp = otpGenerator.generate(6, {
      digits: true,
      upperCaseAlphabets: false,
      specialChars: false,
    });
    console.log("otp : ", otp);

    if (email) {
      // Send OTP to email
      const emailSent = await sendEmail(req.body.email, 'OTP for registration', `Add This OTP ${otp} to register`);
      if (!emailSent) {
        return res.status(404).json({
          success: false,
          message: "Email Not Valid",
        });
      }
      // Insert into otpModel
      const otpEntry = new otpModel({
        otp: otp,
        email: email
      });
      await otpEntry.save();
    }

    if (phoneno) {
      console.log("length", req.body.phoneno.toString().length);
      var length = req.body.phoneno.toString().length;
      if (length < 6 || length > 12) {
        return res.status(422).json({
          success: false,
          message: "Number digits should be 6-12",
        });
      }
      // Sending OTP to upcoming user number for register verification
      const messageSent = await sendMessage(phoneno, `Add This OTP ${otp} to register`);
      if (!messageSent) {
        return res.status(404).json({
          success: false,
          message: "Number Not Valid",
        });
      }
      // Insert into otpModel
      const otpEntry = new otpModel({
        otp: otp,
        phoneno: phoneno
      });
      await otpEntry.save();
    }

    return res.status(200).json({
      success: true,
      message: "OTP has been sent.",
    });
  } catch (err: any) {
    console.log(err);
    if (err.isJoi) {
      return res.status(422).json({
        success: false,
        message: err.details[0].message,
      });
    } else {
      return res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
};

export const confirmOtpHandler = async (req: Request, res: Response, next: NextFunction) => {
  // ... existing code ...
  try {
    console.log(req.body.otp);
    //Finding number with given otp
    otpModel.findOne({ otp: req.body.otp }).then(async (otpProfile) => {
      console.log("user", otpProfile);
      const updatedOtp = await otpModel.updateOne(
        { otp: req.body.otp },
        {
          $set: {
            otp: null,
          },
        }
      );
      //Find if any otp exists
      if (otpProfile) {
        res.status(200).send({
          success: true,
          otpProfile: otpProfile,
          message: "OTP Successful, User Can Register",
        });
      } else {
        //send fail response if otp doesn't exists

        res.status(404).send({
          success: false,
          message: "Invalid Otp",
        });
      }
    });
  } catch (err: any) {
    console.log(err);
    if (err.isJoi) {
      res.status(422).json({
        success: false,
        message: err.details[0].message,
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
};

export const forgetPasswordHandler = async (req: Request, res: Response, next: NextFunction) => {
  // ... existing code ...
  try {
    console.log("U are ", req.body);
    const { email, phoneno } = req.body;
    if (email) {
      userModel
        .findOne({
          email: req.body.email,
        })
        .then(async (user: DocumentType<User> | null) => {
          console.log("user", user);
          //Checking If User Exists
          if (!user) {
            return res.status(404).json({
              success: false,
              message: "User not found with this Email!",
            });
          }
          //Creating Reset OTP for SMS
          var otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            specialChars: false,
          });

          const number = req.body.phoneno;
          console.log("numberrr: ", number);

          //Sending Reset OTP to email
          const emailSent = await sendEmail(req.body.email, 'Reset Password', `Reset Password OTP: ${otp}`);

          if (!emailSent) {
            return console.log("error occurs");
          }


          user.resetPasswordOtp = otp;
          return user.save();
        })
        .then((result: any) => {
          return res.status(200).send({
            success: true,
            message: "Reset Password Email sent",
          });
        })
        .catch((err: any) => {
          console.log(err);
        });
    } else if (phoneno) {
      userModel
        .findOne({
          phoneno: req.body.phoneno,
        })
        .then(async (user) => {
          console.log("user", user);
          //Checking If User Exists
          if (!user) {
            return res.status(404).json({
              success: false,
              message: "User not found with this Email!",
            });
          }
          //Creating Reset OTP for SMS
          var otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            specialChars: false,
          });

          const number = req.body.phoneno;
          console.log("numberrr: ", number);

          //Sending Reset OTP to phone
          const messageSent = await sendMessage(number, `Reset Password OTP: ${otp}`);

          if (!messageSent) {
            return console.log("error occurs");
          }

          user.resetPasswordOtp = otp;
          return user.save();
        })
        .then((result) => {
          return res.status(200).send({
            success: true,
            message: "Reset Password message sent",
          });
        })
        .catch((err) => {
          console.log(err);
        });
    }

  } catch (err: any) {
    console.log("err.isJoi: ", err);
    if (err.isJoi) {
      res.status(422).json({
        success: false,
        message: err.details[0].message,
      });
    } else {
      return res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
};

export const verifyOTPHandler = async (req: Request, res: Response, next: NextFunction) => {
  // ... existing code ...
  try {
    console.log("U are ", req.body);
    //Finding user with the reset OTP
    userModel
      .findOne({ resetPasswordOtp: req.body.resetPasswordOtp })
      .then((user) => {
        //If User don't exist with the given resetOTP, give error
        console.log("user ", user)
        if (!user) {
          return res.status(404).json({
            success: false,
            message: "Invalid OTP",
          });
        } else {
          //If User exists with the given resetOTP then send success
          return res.status(200).json({
            success: true,
            user: user,
            message: "OTP Verified. User Can Change The Password",
          });
        }
      });
  } catch (err: any) {
    console.log(err);
    if (err.isJoi) {
      res.status(422).json({
        success: false,
        message: err.details[0].message,
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
};

export const resetPasswordHandler = async (req: Request, res: Response, next: NextFunction) => {
  // ... existing code ...
  try {
    console.log("req.body", req.body);
    try {
      //Encrypting new password
      let encryptedPassword = await bcrypt.hash(req.body.password, saltRounds);
      console.log("encryptedPassword: ", encryptedPassword);
      //Updating password
      const updatePassword = await userModel.updateOne(
        { resetPasswordOtp: req.body.otp },
        {
          $set: {
            resetPasswordOtp: null,
            password: encryptedPassword
          },
        }
      );
      console.log("updatePassword: ", updatePassword);
      if (updatePassword?.modifiedCount > 0)
        return res.status(200).json({
          success: true,
          message: "Password Updated",
        });
      else
        return res.status(401).json({
          success: false,
          message: "Otp not valid",
        });
    } catch (err) {
      res.status(500).json({
        success: false,
        message: "internal server error",
      });
    }
  } catch (err: any) {
    console.log("err.isJoi: ", err);
    if (err.isJoi) {
      res.status(422).json({
        success: false,
        message: err.details[0].message,
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Internal Server Error",
      });
    }
  }
};

export const getRolesHandler = async (req: Request, res: Response, next: NextFunction) => {
  // ... existing code ...
  try {
    const roles = await Role.find({});
    return res.status(200).json({
      success: true,
      roles: roles,
    });
  } catch (err: any) {
    console.log(err);
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};

// Refresh tokens
const logout = (res: Response) => {
  res.cookie("access_token", "", { maxAge: 1 });
  res.cookie("refresh_token", "", { maxAge: 1 });
  res.cookie("logged_in", "", {
    maxAge: 1,
  });
};

export const refreshAccessTokenHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Get the refresh token from cookie
    const refresh_token = req.cookies.refresh_token as string;

    // Validate the Refresh token
    const decoded = verifyJwt<{ sub: string }>(
      refresh_token,
      "refreshTokenPublicKey"
    );
    const message = "Could not refresh access token";
    if (!decoded) {
      return next(new AppError(message, 403));
    }

    // Check if the user has a valid session
    const session = await redisClient.get(decoded.sub);
    if (!session) {
      return next(new AppError(message, 403));
    }

    // Check if the user exist
    const user = await findUserById(JSON.parse(session)._id);

    if (!user) {
      return next(new AppError(message, 403));
    }

    // Sign new access token
    const access_token = signJwt({ sub: user._id }, "accessTokenPrivateKey", {
      expiresIn: `${config.get<number>("accessTokenExpiresIn")}m`,
    });

    // Send the access token as cookie
    res.cookie("access_token", access_token, accessTokenCookieOptions);
    res.cookie("logged_in", true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    // Send response
    res.status(200).json({
      status: "success",
      access_token,
    });
  } catch (err: any) {
    next(err);
  }
};

export const logoutHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = res.locals.user;
    await redisClient.del(user._id);
    logout(res);
    return res.status(200).json({ status: "success" });
  } catch (err: any) {
    next(err);
  }
};
