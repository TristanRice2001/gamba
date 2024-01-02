import { Controller, useForm } from "react-hook-form";
import ReCAPTCHA from "react-google-recaptcha";
import { apiLogin } from "../../api/auth";
import { LoginRequest } from "../../types/api/auth";

const Login = () => {
  const { register, handleSubmit, control } = useForm<LoginRequest>();

  const onValidSubmit = async (form: LoginRequest) => {
    console.log(form);
    try {
      const res = await apiLogin(form);
    } catch {
      console.log("here");
    }

    console.log("success");
  };

  return (
    <form onSubmit={handleSubmit(onValidSubmit)}>
      <label htmlFor="email">Email / Username</label>
      <input {...register("emailOrUsername")} id="email" />

      <label htmlFor="email">Password</label>
      <input {...register("password")} id="email" />

      <Controller
        control={control}
        name="recaptchaToken"
        render={({ field }) => (
          <ReCAPTCHA
            onChange={field.onChange}
            sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY || ""}
          />
        )}
      />
      <button type="submit">Submit</button>
    </form>
  );
};
export default Login;
