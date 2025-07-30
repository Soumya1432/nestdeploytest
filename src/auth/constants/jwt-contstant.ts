
export const jwtConstants = {
  accessTokenSecret:
    process.env.JWT_ACCESS_TOKEN_SECRET ||
    'your_access_token_secret_32_chars_long_hot',
  refreshTokenSecret:
    process.env.JWT_REFRESH_TOKEN_SECRET ||
    'your_refresh_token_secret_32_chars_long_strong',
  accessTokenExpirationMs: 15 * 60 * 1000, // 15 minutes
  refreshTokenExpirationMs: 7 * 24 * 60 * 60 * 1000, // 7 days
};
