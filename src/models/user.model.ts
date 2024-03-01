import {
  DocumentType,
  getModelForClass,
  index,
  modelOptions,
  pre,
  prop,
  Ref,
} from '@typegoose/typegoose';
import bcrypt from 'bcryptjs';
import { Role } from './role.model';// assuming you have a company.model.ts file

@index({ email: 1 })
@pre<User>('save', async function () {
  // Hash password if the password is new or was updated
  if (!this.isModified('password')) return;

  // Hash password with costFactor of 12
  this.password = await bcrypt.hash(this.password, 12);
})
@modelOptions({
  schemaOptions: {
    // Add createdAt and updatedAt fields
    timestamps: true,
  },
})

// Export the User class to be used as TypeScript type
export class User {
  @prop({ required: true })
  firstname: string;

  @prop({ required: true })
  lastname: string;

  @prop({ required: true })
  name: string;

  @prop()
  gender: string;

  @prop({ unique: true, required: true })
  email: string;

  @prop()
  phoneno: string;

  @prop({ required: true, minlength: 8, maxLength: 32, select: false })
  password: string;

  @prop({ ref: () => Role })
  role: Ref<Role>;

  @prop()
  profilepic: string;

  @prop()
  address: string;

  @prop({ default: false })
  isDeleted: boolean;

  @prop()
  resetPasswordOtp: string;

  // Instance method to check if passwords match
  async comparePasswords(hashedPassword: string, candidatePassword: string) {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  }
}

// Create the user model from the User class
const userModel = getModelForClass(User);
export default userModel;
