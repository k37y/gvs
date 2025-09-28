# Sustaining Project Branch - Cursor Rules

## Project Context
This is a **sustaining project branch** with strict maintenance and compatibility requirements.

## Critical Constraints

### Go Version Compatibility (NON-NEGOTIABLE)
- **Go major or minor version CANNOT be changed** from current version
- Go version changes affect Kubernetes version compatibility
- Any suggested changes that modify go.mod version requirements must be rejected and highlighted
- Dependencies must remain compatible with current Go version

### Change Validation Checklist
Before approving ANY code changes, verify:

1. **Sustaining Branch Compliance**
   - [ ] Change aligns with sustaining project goals (bug fixes, security patches, minimal enhancements)
   - [ ] No unnecessary feature additions or architectural changes
   - [ ] Maintains backward compatibility

2. **Go Version Stability**
   - [ ] No changes to go.mod Go major or minor version declaration
   - [ ] No introduction of newer Go language features incompatible with current Go version
   - [ ] Dependencies remain compatible with current Go version

3. **Last Unstaged Change Analysis**
   - [ ] Review git diff to understand scope of changes
   - [ ] Verify changes follow sustaining project principles
   - [ ] Check for any Go version impacts

4. **Functionality Impact Assessment**
   - [ ] No breaking changes to existing APIs
   - [ ] No performance regressions
   - [ ] Maintains cross-binary compatibility
   - [ ] Preserves existing functionality

5. **Change Appropriateness Review**
   - [ ] Is this the minimal change needed to achieve the goal?
   - [ ] Are there simpler alternatives that require less maintenance?
   - [ ] Does the change introduce technical debt?
   - [ ] Is proper testing included?

### Maintenance Minimization
- **Minimal changes only**: Make the smallest possible change to achieve the goal
- Prefer configuration over code changes
- Avoid introducing new dependencies unless absolutely necessary
- Use existing patterns and structures
- Document any complex changes for future maintainers

### Pre-commit Validation
Always run these checks before committing:
```bash
# Check last unstaged changes
git diff --name-only
git diff

# Verify Go compatibility
go version
go mod verify

# Find build and test method and execute all of them. Ex:
go build ./...
go test ./...
```

### Sustaining Branch Best Practices
1. **Security patches** - Apply with minimal code impact
2. **Bug fixes** - Target root cause with surgical precision
3. **Dependency updates** - Only for security/critical bugs, verify compatibility
4. **Performance fixes** - Measure before/after, ensure no regressions
5. **Documentation** - Update only when functionality changes

### Rejection Criteria
Automatically reject changes that:
- Modify Go major or minor version in go.mod
- Add unnecessary features or complexity
- Break backward compatibility
- Introduce new major dependencies
- Refactor working code without clear benefit
- Add experimental or bleeding-edge features

## Emergency Override
For critical security issues, these rules may be temporarily suspended with explicit approval and documentation of:
- Security impact assessment
- Risk/benefit analysis
- Rollback plan
- Future migration strategy

Remember: This is a sustaining branch. Stability and minimal maintenance burden take precedence over new features or architectural improvements.
