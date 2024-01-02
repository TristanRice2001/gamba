interface Props {
  [key: string]: any;
}

const Input = ({ ...props }: Props) => {
  return (
    <>
      <label htmlFor="email">Username</label>
      <input {...props} />
    </>
  );
};
