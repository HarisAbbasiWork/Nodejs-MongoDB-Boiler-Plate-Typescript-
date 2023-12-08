import { getModelForClass, modelOptions, prop } from '@typegoose/typegoose';

@modelOptions({
  schemaOptions: {
    timestamps: true,
  },
})
export class Role {
  @prop({ required: true })
  roleName: string;
}

const roleModel = getModelForClass(Role);
export default roleModel;
