import { useForm, Controller } from "react-hook-form";
import { AuthRequest } from "../../types/api/auth";
import { apiRegister } from "../../api/auth";
import ReCaptcha from "react-google-recaptcha";

type RegisterForm = AuthRequest;

const Register = () => {
  const { register, handleSubmit, control } = useForm<RegisterForm>();

  const onValidSubmit = async (form: RegisterForm) => {
    console.log(form);
    try {
      const res = await apiRegister(form);
    } catch {
      console.log("here");
    }

    console.log("success");
  };

  return (
    <form onSubmit={handleSubmit(onValidSubmit)}>
      <label htmlFor="email">Email</label>
      <input {...register("email")} id="email" />

      <label htmlFor="email">Username</label>
      <input {...register("username")} id="email" />

      <label htmlFor="email">Password</label>
      <input {...register("password")} type="password" id="email" />

      <Controller
        control={control}
        name="recaptchaToken"
        render={({ field }) => (
          <ReCaptcha
            onChange={field.onChange}
            sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY || ""}
          />
        )}
      />
      <button type="submit">Submit</button>
    </form>
  );
};

export default Register;
