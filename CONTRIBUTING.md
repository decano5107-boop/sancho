# Contributing

Thanks for taking the time. This project is maintained by one person, so a little structure
keeps it sustainable.

## Before you open a pull request

1. **Open an issue first** for anything larger than a typo. It avoids work that will not merge.
2. Keep pull requests focused — one concern per PR.
3. Match the surrounding style. There is no separate style guide; the existing files are it.

## What gets merged quickly

- Bug fixes with a clear reproduction
- Documentation that removes a real point of confusion
- Small, self-contained improvements

## What needs discussion first

- New dependencies
- Changes to the public interface or configuration format
- Anything that changes default behavior

## Ground rules

- **Never commit secrets, credentials, real customer data, or third-party logos and trademarks.**
  Pull requests containing any of these are closed, not fixed.
- Use fictional data in examples. `example.com` for domains, obviously fake names and numbers.
- By contributing, you agree your contribution is licensed under this repository's license.

## Development

The README's **Set up** section covers installation. Run the tests with
`python3 -m unittest discover -s tests`; a new hook or rule comes with tests derived from what it
must prevent, not only from the case that prompted it. If setup is unclear, that is a bug — please
report it.
