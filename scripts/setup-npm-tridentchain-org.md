# Create @tridentchain on npm

npm organizations are created on the website (not via CLI).

## Steps

1. Log in locally:

   ```bash
   npm login
   ```

2. Create the organization (free plan is enough for public packages):

   - Open https://www.npmjs.com/org/create
   - Organization name: `tridentchain`
   - Plan: **Unlimited public packages** (free)

3. Verify:

   ```bash
   npm org ls tridentchain
   ```

4. Publish the CLI wrapper:

   ```bash
   cd npm-wrapper
   npm publish --access public
   ```

If the name `tridentchain` is taken, pick another org name and update `npm-wrapper/package.json` (`name` field).
