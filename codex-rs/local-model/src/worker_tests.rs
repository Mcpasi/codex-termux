use super::*;

#[test]
fn helper_leases_exclude_other_coordinators_and_release_on_disconnect() -> Result<()> {
    let state = Arc::new(Mutex::new(LeaseState::default()));
    let first_id = [1; 16];
    let second_id = [2; 16];
    let first = PoolLease::acquire(Arc::clone(&state), first_id)?;
    let second_channel = PoolLease::acquire(Arc::clone(&state), first_id)?;
    assert!(PoolLease::acquire(Arc::clone(&state), second_id).is_err());
    drop(first);
    assert!(PoolLease::acquire(Arc::clone(&state), second_id).is_err());
    drop(second_channel);
    let _next = PoolLease::acquire(state, second_id)?;
    Ok(())
}
