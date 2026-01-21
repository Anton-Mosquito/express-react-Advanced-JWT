export default class UserDto {
  email: string;
  id: string;
  isActivated: boolean;

  constructor(model: any) {
    this.email = model.email;
    this.id = model.id;
    this.isActivated = model.isActivated;
  }
}
