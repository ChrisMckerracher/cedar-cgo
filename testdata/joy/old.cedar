@id("b0")
permit(principal in Joy::Account::"acct0", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj0")
when { context.deviceLevel >= 0 };
@id("b1")
permit(principal in Joy::Account::"acct1", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj1")
when { context.deviceLevel >= 1 };
@id("b2")
permit(principal in Joy::Account::"acct2", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj2")
when { context.deviceLevel >= 2 };
@id("b3")
permit(principal in Joy::Account::"acct3", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj3")
when { context.deviceLevel >= 0 };
@id("b4")
permit(principal in Joy::Account::"acct4", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj4")
when { context.deviceLevel >= 1 };
@id("b5")
permit(principal in Joy::Account::"acct5", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj5")
when { context.deviceLevel >= 2 };
@id("b6")
permit(principal in Joy::Account::"acct6", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj6")
when { context.deviceLevel >= 0 };
@id("b7")
permit(principal in Joy::Account::"acct7", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj0")
when { context.deviceLevel >= 1 };
@id("b8")
permit(principal in Joy::Account::"acct8", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj1")
when { context.deviceLevel >= 2 };
@id("b9")
permit(principal in Joy::Account::"acct9", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj2")
when { context.deviceLevel >= 0 };
@id("b10")
permit(principal in Joy::Account::"acct0", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj3")
when { context.deviceLevel >= 1 };
@id("b11")
permit(principal in Joy::Account::"acct1", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj4")
when { context.deviceLevel >= 2 };
@id("b12")
permit(principal in Joy::Account::"acct2", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj5")
when { context.deviceLevel >= 0 };
@id("b13")
permit(principal in Joy::Account::"acct3", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj6")
when { context.deviceLevel >= 1 };
@id("b14")
permit(principal in Joy::Account::"acct4", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj0")
when { context.deviceLevel >= 2 };
@id("b15")
permit(principal in Joy::Account::"acct5", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj1")
when { context.deviceLevel >= 0 };
@id("b16")
permit(principal in Joy::Account::"acct6", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj2")
when { context.deviceLevel >= 1 };
@id("b17")
permit(principal in Joy::Account::"acct7", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj3")
when { context.deviceLevel >= 2 };
@id("b18")
permit(principal in Joy::Account::"acct8", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj4")
when { context.deviceLevel >= 0 };
@id("b19")
permit(principal in Joy::Account::"acct9", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj5")
when { context.deviceLevel >= 1 };
@id("b20")
permit(principal in Joy::Account::"acct0", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj6")
when { context.deviceLevel >= 2 };
@id("b21")
permit(principal in Joy::Account::"acct1", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj0")
when { context.deviceLevel >= 0 };
@id("b22")
permit(principal in Joy::Account::"acct2", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj1")
when { context.deviceLevel >= 1 };
@id("b23")
permit(principal in Joy::Account::"acct3", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj2")
when { context.deviceLevel >= 2 };
@id("b24")
permit(principal in Joy::Account::"acct4", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj3")
when { context.deviceLevel >= 0 };
@id("b25")
permit(principal in Joy::Account::"acct5", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj4")
when { context.deviceLevel >= 1 };
@id("b26")
permit(principal in Joy::Account::"acct6", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj5")
when { context.deviceLevel >= 2 };
@id("b27")
permit(principal in Joy::Account::"acct7", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj6")
when { context.deviceLevel >= 0 };
@id("b28")
permit(principal in Joy::Account::"acct8", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj0")
when { context.deviceLevel >= 1 };
@id("b29")
permit(principal in Joy::Account::"acct9", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj1")
when { context.deviceLevel >= 2 };
@id("b30")
permit(principal in Joy::Account::"acct0", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj2")
when { context.deviceLevel >= 0 };
@id("b31")
permit(principal in Joy::Account::"acct1", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj3")
when { context.deviceLevel >= 1 };
@id("b32")
permit(principal in Joy::Account::"acct2", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj4")
when { context.deviceLevel >= 2 };
@id("b33")
permit(principal in Joy::Account::"acct3", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj5")
when { context.deviceLevel >= 0 };
@id("b34")
permit(principal in Joy::Account::"acct4", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj6")
when { context.deviceLevel >= 1 };
@id("b35")
permit(principal in Joy::Account::"acct5", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj0")
when { context.deviceLevel >= 2 };
@id("b36")
permit(principal in Joy::Account::"acct6", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj1")
when { context.deviceLevel >= 0 };
@id("b37")
permit(principal in Joy::Account::"acct7", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj2")
when { context.deviceLevel >= 1 };
@id("b38")
permit(principal in Joy::Account::"acct8", action in [Joy::Action::"session.read", Joy::Action::"session.write", Joy::Action::"terminal.open", Joy::Action::"file.read", Joy::Action::"file.write"], resource in Joy::Project::"proj3")
when { context.deviceLevel >= 2 };
@id("b39")
permit(principal in Joy::Account::"acct9", action in [Joy::Action::"session.read", Joy::Action::"file.read"], resource in Joy::Project::"proj4")
when { context.deviceLevel >= 0 };
@id("c-terminal-validated")
forbid(principal, action == Joy::Action::"terminal.open", resource) unless { context.deviceLevel >= 2 };
@id("c-machine-attested")
forbid(principal, action in [Joy::Action::"session.write", Joy::Action::"file.write", Joy::Action::"terminal.open"], resource) unless { context.machineAttested };
@id("c-android-sec")
forbid(principal, action, resource) when { context.platform.os == "android" && context.platform.securityLevel < 2 && context.deviceLevel < 2 };
@id("c-night-writes")
forbid(principal, action == Joy::Action::"file.write", resource) when { context.now.toTime() >= duration("23h") && context.deviceLevel < 2 };
@id("c-lan-only")
forbid(principal, action == Joy::Action::"terminal.open", resource) unless { context.sourceIp.isInRange(ip("10.0.0.0/8")) || context.sourceIp.isLoopback() };
