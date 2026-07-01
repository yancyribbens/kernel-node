mod common;

use common::TestNode;

#[test]
fn echoes_over_control_socket_and_stops() {
    let node = TestNode::start();

    let out = node.cli(&["echo", "kernel-node"]);
    assert!(
        out.status.success(),
        "cli echo failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("kernel-node"),
        "unexpected echo output: {stdout}"
    );

    node.stop();
}
