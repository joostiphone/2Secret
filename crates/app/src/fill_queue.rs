//! The logins the user allowed an agent to fill, waiting for a browser.
//! Each job is offered to every connected browser once (a profile of a
//! browser is a connection of its own) until one reports it filled; the
//! agent's reply handle `R` travels with the job. Pure, so it can be tested
//! without sockets; `agent_access` keeps the one instance behind a mutex.

use std::collections::HashSet;
use std::time::Instant;

use serde_json::Value;
use twosecret_core::agent::{AgentError, FillCommand, FillOutcome, FillResult};

pub struct PendingFill<R> {
    /// The id of the agent's request (for cancelling).
    pub request_id: u64,
    pub command: FillCommand,
    pub reply: R,
    /// The website, for the message to the agent.
    pub host: String,
    pub deadline: Instant,
    /// Connections that got the job.
    tried: HashSet<u64>,
    /// The connection that has it now.
    in_flight: Option<u64>,
}

pub struct FillQueue<R> {
    jobs: Vec<PendingFill<R>>,
}

impl<R> FillQueue<R> {
    pub const fn new() -> Self {
        Self { jobs: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    pub fn push(&mut self, request_id: u64, command: FillCommand, reply: R, host: String, deadline: Instant) {
        self.jobs.push(PendingFill {
            request_id,
            command,
            reply,
            host,
            deadline,
            tried: HashSet::new(),
            in_flight: None,
        });
    }

    /// The oldest job that is not with another browser and that `conn` has
    /// not tried yet; it is now with `conn`.
    pub fn take(&mut self, conn: u64, now: Instant) -> Option<FillCommand> {
        let job =
            self.jobs.iter_mut().find(|j| j.in_flight.is_none() && !j.tried.contains(&conn) && j.deadline > now)?;
        job.tried.insert(conn);
        job.in_flight = Some(conn);
        Some(job.command.clone())
    }

    /// Connection `conn` reported on job `job_id`. `browser` is its name for
    /// the agent, `connected` the connections that are still there. Returns
    /// what to tell the agent when the job is finished; `None` while another
    /// browser may still try.
    pub fn result(
        &mut self,
        job_id: &str,
        conn: u64,
        outcome: FillOutcome,
        submitted: bool,
        browser: &str,
        connected: &[u64],
    ) -> Option<(R, Result<Value, AgentError>)> {
        let at = self.jobs.iter().position(|j| j.command.id == job_id && j.in_flight == Some(conn))?;
        if outcome == FillOutcome::Filled {
            let job = self.jobs.remove(at);
            let result = serde_json::to_value(FillResult { filled: true, browser: browser.to_string(), submitted })
                .unwrap_or(Value::Null);
            return Some((job.reply, Ok(result)));
        }
        let job = &mut self.jobs[at];
        job.in_flight = None;
        if connected.iter().any(|c| !job.tried.contains(c)) {
            return None;
        }
        let job = self.jobs.remove(at);
        let where_ = if job.tried.len() > 1 { "your browsers" } else { browser };
        Some((job.reply, Err(AgentError::fill_failed(outcome, &job.host, where_))))
    }

    /// Jobs past their deadline, with the error for their agents.
    pub fn expire(&mut self, now: Instant) -> Vec<(R, AgentError)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.jobs.len() {
            if self.jobs[i].deadline <= now {
                let job = self.jobs.remove(i);
                let message = if job.tried.is_empty() {
                    format!(
                        "no browser picked up the login for {}: is a browser with the 2Secret extension open?",
                        job.host
                    )
                } else {
                    format!(
                        "the browser did not fill the login for {} in time: open the sign-in page and make it the active tab",
                        job.host
                    )
                };
                out.push((job.reply, AgentError::new(AgentError::FILL_FAILED, message)));
            } else {
                i += 1;
            }
        }
        out
    }

    /// Connection `conn` went away: what it held may go to another browser.
    pub fn drop_conn(&mut self, conn: u64) {
        for job in &mut self.jobs {
            if job.in_flight == Some(conn) {
                job.in_flight = None;
            }
        }
    }

    /// The agent stopped waiting for request `request_id`.
    pub fn remove_request(&mut self, request_id: u64) -> Option<R> {
        let at = self.jobs.iter().position(|j| j.request_id == request_id)?;
        Some(self.jobs.remove(at).reply)
    }

    /// Everything, for instance when 2Secret locks (the secrets are wiped
    /// with the commands).
    pub fn clear(&mut self) -> Vec<R> {
        self.jobs.drain(..).map(|j| j.reply).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn command(id: &str) -> FillCommand {
        FillCommand {
            id: id.into(),
            url: "https://github.com/login".into(),
            rules: Vec::new(),
            username: "octo".into(),
            password: "hunter2".into(),
            code: String::new(),
            submit: true,
        }
    }

    #[test]
    fn jobs_go_to_each_browser_once() {
        let mut q: FillQueue<u32> = FillQueue::new();
        let now = Instant::now();
        let later = now + Duration::from_secs(30);
        assert!(q.is_empty());
        q.push(1, command("f-1"), 11, "github.com".into(), later);
        assert!(!q.is_empty());
        // Browser 1 takes it; browser 2 gets nothing while it is in flight.
        assert_eq!(q.take(1, now).unwrap().id, "f-1");
        assert!(q.take(2, now).is_none());
        assert!(q.take(1, now).is_none());
        // Browser 1 has no tab; browser 2 is still there, so the job waits for it.
        assert!(q.result("f-1", 1, FillOutcome::NoTab, false, "chrome", &[1, 2]).is_none());
        assert!(q.take(1, now).is_none(), "tried already");
        assert_eq!(q.take(2, now).unwrap().id, "f-1");
        let (reply, result) = q.result("f-1", 2, FillOutcome::Filled, true, "firefox", &[1, 2]).unwrap();
        assert_eq!(reply, 11);
        let value = result.unwrap();
        assert_eq!(value["filled"], true);
        assert_eq!(value["browser"], "firefox");
        assert_eq!(value["submitted"], true);
        assert!(q.is_empty());

        // Only one browser, and it finds nothing to fill: the agent hears why.
        q.push(2, command("f-2"), 22, "github.com".into(), later);
        assert_eq!(q.take(1, now).unwrap().id, "f-2");
        let (reply, result) = q.result("f-2", 1, FillOutcome::Nothing, false, "chrome", &[1]).unwrap();
        assert_eq!(reply, 22);
        let err = result.unwrap_err();
        assert_eq!(err.code, AgentError::FILL_FAILED);
        assert!(err.message.contains("nothing to fill") && err.message.contains("chrome"), "{}", err.message);
        // A report from a connection that does not hold the job is ignored.
        assert!(q.result("f-2", 1, FillOutcome::Filled, false, "chrome", &[1]).is_none());

        // Two browsers both fail: "your browsers".
        q.push(3, command("f-3"), 33, "github.com".into(), later);
        q.take(1, now);
        assert!(q.result("f-3", 1, FillOutcome::NoTab, false, "chrome", &[1, 2]).is_none());
        q.take(2, now);
        let (_, result) = q.result("f-3", 2, FillOutcome::NoTab, false, "firefox", &[1, 2]).unwrap();
        assert!(result.unwrap_err().message.contains("your browsers"));
    }

    #[test]
    fn jobs_expire_and_follow_connections() {
        let mut q: FillQueue<u32> = FillQueue::new();
        let now = Instant::now();
        q.push(1, command("f-1"), 11, "a.example".into(), now + Duration::from_secs(1));
        q.push(2, command("f-2"), 22, "b.example".into(), now + Duration::from_secs(5));
        assert_eq!(q.take(7, now).unwrap().id, "f-1");
        // The connection dies: the job is free again for others, not for 7.
        q.drop_conn(7);
        assert_eq!(q.take(8, now).unwrap().id, "f-1");
        assert_eq!(q.take(7, now).unwrap().id, "f-2");
        let expired = q.expire(now + Duration::from_secs(2));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, 11);
        assert!(expired[0].1.message.contains("did not fill"), "{}", expired[0].1.message);
        assert!(q.take(9, now + Duration::from_secs(6)).is_none(), "past its deadline");
        q.push(3, command("f-3"), 33, "c.example".into(), now + Duration::from_secs(1));
        let expired = q.expire(now + Duration::from_secs(2));
        assert_eq!(expired[0].0, 33);
        assert!(expired[0].1.message.contains("no browser picked up"));
        assert_eq!(q.remove_request(2), Some(22));
        assert_eq!(q.remove_request(2), None);
        q.push(4, command("f-4"), 44, "d.example".into(), now + Duration::from_secs(9));
        assert_eq!(q.clear(), vec![44]);
        assert!(q.is_empty());
    }
}
