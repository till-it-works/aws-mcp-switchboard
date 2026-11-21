import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    passWithNoTests: true,
    // Vite injects BASE_URL="/" into process.env; the Switchboard reads BASE_URL as a deployment override.
    env: { BASE_URL: "" },
  },
});
