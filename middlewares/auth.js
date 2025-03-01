import { User } from "../models/userSchema.js";
import jwt from "jsonwebtoken";
import ErrorHandler from "./error.js";
import { catchAsyncErrors } from "../middlewares/catchAsyncErrors.js";

export const isAuthenticated = catchAsyncErrors(async (req, res, next) => {
  console.log("Cookies received:", req.cookies); // Debugging

  const token = req.cookies.token;
  if (!token) {
    console.log("Authentication failed: Token is missing.");
    return next(new ErrorHandler("Authentication token is missing.", 401));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    console.log("Decoded Token:", decoded); // Log decoded token

    req.user = await User.findById(decoded.id);
    if (!req.user) {
      console.log("Authentication failed: User not found.");
      return next(new ErrorHandler("User not found.", 401));
    }

    next();
  } catch (error) {
    console.error("JWT Verification Error:", error.message);
    return next(new ErrorHandler("Invalid or expired token.", 401));
  }
});




export const isAuthorized = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorHandler(
          `${req.user.role} not allowed to access this resouce.`,
          403
        )
      );
    }
    next();
  };
};