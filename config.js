// config.js
import dotenv from 'dotenv';
dotenv.config();

export const API_KEYS = {
  hunter: process.env.HUNTER_API_KEY,
  leakcheck: process.env.LEAKCHECK_API_KEY,
  shodan: process.env.SHODAN_API_KEY,
  whoisxml: process.env.WHOISXML_API_KEY,
  osintindustries: process.env.OSINTindustries_API_KEY
};


