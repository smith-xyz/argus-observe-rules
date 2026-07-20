fn format_ssh_command(host: &str, user: &str) -> String {
    format!("ssh {}@{}", user, host)
}
