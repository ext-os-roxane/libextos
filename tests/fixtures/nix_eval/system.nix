{
  name = "workstation";
  native_pm = "debian";
  kernel = "6.8.2-extos";

  packages = [
    "archlinux/htop=3.3.0-1"
    "debian/bash"
    "ripgrep=14.1.0"
    { origin = "alpine"; name = "musl"; version = "1.2.5-r0"; }
    { name = "glibc"; }
  ];

  services = [ "sshd" "chronyd" { name = "networkd"; } ];
}
