import axios from "axios";

const api = axios.create({
  baseURL: "http://160.20.22.99:5207/sistema",
});

export default api;
