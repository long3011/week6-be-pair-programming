const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");

const userSchema = mongoose.Schema(
  {
  name: { type: String, 
    required: [true,"name"] },
  email: { type: String, 
    required: [true,"email"], 
    unique: true },
  password: { type: String, 
    required: [true,"password"] },
  phone_number: { type: String, 
    required: [true,"phone_number"] },
  gender: { type: String, required: 
    [true,"gender"] },
  date_of_birth: { type: Date, 
    required: [true,"dob"] },
  membership_status: { type: String, 
    required: [true,"membership"]},
},
  {
    timestamps: true,
  }
);

// static signup method
userSchema.statics.signup = async function (name, email, password
  , phone_number, gender, date_of_birth, membership_status
) {
  //validation
  if ((!name , !email|| !password|| !phone_number
    || !gender ||!date_of_birth|| !membership_status
  )) {
    throw Error("Please add all fields");
  }
  if (!validator.isEmail(email)) {
    throw Error("Email not valid");
  }
  if (!validator.isStrongPassword(password)) {
    throw Error("Password not strong enough");
  }

  const userExists = await this.findOne({ email });

  if (userExists) {
    throw new Error("User already exists");
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = await this.create({
    name,
    email,
    password: hashedPassword,
    phone_number,
    gender,
    date_of_birth,
    membership_status,
  });

  return user;
};

// static login method
userSchema.statics.login = async function (email, password) {
  if (!email || !password) {
    throw Error("All fields must be filled");
  }

  const user = await this.findOne({ email });
  if (!user) {
    throw Error("Incorrect email");
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    throw Error("Incorrect password");
  }

  return user;
};

module.exports = mongoose.model("User", userSchema);



// What are these functions (userSchema.statics.signup() and userSchema.statics.login())?
// add static methods to the Mongoose schema for signup and login

// Why are they used?
// They encapsulate the logic for user registration and authentication within the model itself,
// promoting code organization and reusability.

// What are the pros and cons of using this approach?
// Pros:
// 1. Encapsulation: Keeps related logic together.
// 2. Reusability: Can be called from different parts of the application.
// 3. Clarity: Makes it clear that these operations are related to the User model.
// Cons:
// 1. Complexity: Can make the model file larger and more complex.
// 2. Testing: May require more setup for unit testing these methods.

// What alternative approaches are available?
// 1. Service Layer: Implementing a separate service layer for business logic.
// 2. Middleware: Using middleware for authentication and validation.
// 3. Controller Functions: Keeping the logic in controller functions instead of the model.
