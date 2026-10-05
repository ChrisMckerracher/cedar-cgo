package testsupport

const PhotoSchema = `
entity User in [Group];
entity Group;
entity Photo { owner: User, private: Bool };
action view appliesTo { principal: User, resource: Photo, context: { mfa: Bool } };
`

const PhotoPolicies = `
permit(principal, action == Action::"view", resource)
when { resource.owner == principal || !resource.private };

forbid(principal, action, resource)
unless { context.mfa };
`
