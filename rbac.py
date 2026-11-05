"""Role-Based Access Control (RBAC) demo - Software Security, Chapter 04."""

ACTIONS = ["create", "view", "update", "delete"]


class RBAC:
    def __init__(self):
        self.role_permissions = {}   # role -> set of (action, object)
        self.user_roles = {}         # user -> set of roles

    # ---- administration ----
    def add_role(self, role):
        self.role_permissions.setdefault(role, set())

    def assign_permission(self, role, action, obj):
        self.add_role(role)
        self.role_permissions[role].add((action, obj))

    def assign_role(self, user, role):
        if role not in self.role_permissions:
            raise ValueError(f"Unknown role: {role}")
        self.user_roles.setdefault(user, set()).add(role)

    # ---- access check ----
    def is_allowed(self, user, action, obj):
        return any((action, obj) in self.role_permissions[r]
                   for r in self.user_roles.get(user, ()))


def build_system():
    rbac = RBAC()
    perms = {
        "Admin":    ["create", "view", "update", "delete"],
        "Manager":  ["view", "update"],
        "Customer": ["view"],
    }
    for role, actions in perms.items():
        for a in actions:
            rbac.assign_permission(role, a, "Account")
    for user, role in [("Ahmad", "Admin"), ("Sara", "Manager"), ("Omar", "Customer")]:
        rbac.assign_role(user, role)
    return rbac


def show_table(rbac):
    print("\n=== Role -> Permissions on 'Account' ===")
    for role, p in rbac.role_permissions.items():
        print(f"{role:<9}: {', '.join(sorted(a for a, _ in p))}")
    print("\n=== User -> Roles ===")
    for user, roles in rbac.user_roles.items():
        print(f"{user:<6}: {', '.join(roles)}")


def run_tests(rbac):
    print("\n=== Access tests ===")
    print(f"{'User':<7}{'Role':<10}" + "".join(f"{a:<9}" for a in ACTIONS))
    for user, roles in rbac.user_roles.items():
        row = "".join(f"{'ALLOW' if rbac.is_allowed(user, a, 'Account') else 'DENY':<9}"
                      for a in ACTIONS)
        print(f"{user:<7}{', '.join(roles):<10}{row}")


def interactive(rbac):
    print("\n=== Interactive mode (type 'exit' as username to quit) ===")
    while True:
        user = input("Username: ").strip()
        if user.lower() == "exit":
            break
        if user not in rbac.user_roles:
            print("Unknown user.\n")
            continue
        action = input(f"Action {ACTIONS}: ").strip().lower()
        ok = rbac.is_allowed(user, action, "Account")
        print(f"-> {user} {'CAN' if ok else 'CANNOT'} {action} Account\n")


if __name__ == "__main__":
    system = build_system()
    show_table(system)
    run_tests(system)
    interactive(system)
