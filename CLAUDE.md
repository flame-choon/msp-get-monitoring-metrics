# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a monitoring metrics collection service designed to retrieve metrics from AWS CloudWatch and Whatap monitoring services. The project name suggests it's part of an MSP (Managed Service Provider) infrastructure monitoring solution.

## Development Commands

Since this is a new project, the following commands will need to be established based on the technology stack chosen:

### For Node.js/TypeScript projects:
- Build: `npm run build` or `yarn build`
- Test: `npm test` or `yarn test`
- Lint: `npm run lint` or `yarn lint`
- Run locally: `npm start` or `yarn start`
- Run single test: `npm test -- <test-file-path>`

### For Python projects:
- Install dependencies: `pip install -r requirements.txt`
- Run tests: `pytest`
- Lint: `ruff check .` or `pylint src/`
- Run locally: `python main.py` or `python -m src.main`

## Architecture Considerations

When implementing this monitoring metrics collector, consider:

1. **Metrics Sources**
   - AWS CloudWatch: Use AWS SDK for metrics retrieval
   - Whatap: Integration with Whatap API endpoints

2. **Core Components to Implement**
   - Metrics collectors for each service
   - Configuration management for API credentials and endpoints
   - Data transformation layer to normalize metrics
   - Scheduling mechanism for periodic collection
   - Output/storage layer (database, file, or streaming)

3. **Security Patterns**
   - Store credentials in environment variables or AWS Secrets Manager
   - Never commit API keys or tokens to the repository
   - Implement proper error handling for API failures

4. **Testing Strategy**
   - Mock external API calls in unit tests
   - Implement integration tests with test accounts when possible
   - Test metric transformation logic thoroughly

## Key Implementation Notes

- Use async/concurrent processing for fetching metrics from multiple sources
- Implement retry logic with exponential backoff for API calls
- Consider rate limiting to avoid hitting API quotas
- Log all API interactions for debugging and audit purposes