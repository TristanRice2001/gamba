import axios from "axios";

console.log(process.env.NEXT_PUBLIC_API_URL);

const baseAxiosOpts = {
  baseUrl: process.env.NEXT_PUBLIC_API_URL,
};

export const baseInstance = axios.create({
  baseURL: process.env.NEXT_PUBLC_API_URL,
});

export const authenticatedRequest = () =>
  axios.create({
    ...baseAxiosOpts,
    headers: {
      Authorization: `JWT ${localStorage.getItem("token")}`,
    },
  });
