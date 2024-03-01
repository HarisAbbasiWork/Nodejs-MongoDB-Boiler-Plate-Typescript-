import { getModelForClass, modelOptions, prop } from '@typegoose/typegoose';

@modelOptions({
  schemaOptions: {
    timestamps: true,
    expires: 60 * 60 * 24 * 2, // this is the expiry time in seconds
  },
})
export class Otp {
  @prop({ required: false })
  phoneno: number;

  @prop({ required: true })
  otp: string;

  @prop({ required: false })
  messageId: string;

  @prop({ required: false })
  email: string;
}

const otpModel = getModelForClass(Otp);
export default otpModel;
