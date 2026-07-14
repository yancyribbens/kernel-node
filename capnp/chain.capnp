@0x93074320567c5aeb;

interface Chain {
    getTip @0 () -> (height :UInt32, hash :Text);
}
