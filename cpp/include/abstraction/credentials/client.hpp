#pragma once
#include <abstraction/credentials/api/rec.h>
#include <abstraction/ipc/frame.hpp>
namespace abstraction::credentials {
namespace detail {
inline void require(bool ok,const char* what){if(!ok)throw api::ServiceError("invalid_response",what);}
}
// Registers, rotates, revokes and inspects credentials by name in the caller's
// account. Every call is a rights decision on the bound caller; no reply carries
// secret bytes. No call is retried.
class Holder {
public:
 explicit Holder(std::string endpoint):transport_(std::move(endpoint),5000,1u<<20){}
 Holder(std::string endpoint,ipc::Deadline deadline):transport_(std::move(endpoint),deadline,1u<<20){}
 Holder with_server_expectation(std::optional<ipc::ServerExpectation> server)const{auto copy=*this;copy.transport_=transport_.with_server_expectation(std::move(server));return copy;}
 Holder with_cancellation(ipc::CancellationToken token)const{auto copy=*this;copy.transport_=transport_.with_cancellation(std::move(token));return copy;}
 // The caller clears registration.secret after the call.
 api::StoreResult store(const std::string& expected_revision,const api::Registration& registration)const{
  auto transport=transport_;api::HolderClient<ipc::FrameTransport> client(transport);auto r=client.store(expected_revision,registration);
  const bool evaluated=r.outcome==api::StoreOutcome::Stored||r.outcome==api::StoreOutcome::Conflict;
  detail::require(evaluated==r.current.has_value()&&(r.outcome!=api::StoreOutcome::Stored||!r.revision.empty()),"inconsistent store result");return r;
 }
 api::RotateResult rotate(const std::string& expected_revision,const api::Rotation& rotation)const{
  auto transport=transport_;api::HolderClient<ipc::FrameTransport> client(transport);auto r=client.rotate(expected_revision,rotation);
  detail::require(r.outcome!=api::RotateOutcome::Rotated||!r.revision.empty(),"inconsistent rotate result");return r;
 }
 api::RevokeResult revoke(const std::string& expected_revision,const std::string& name)const{
  auto transport=transport_;api::HolderClient<ipc::FrameTransport> client(transport);return client.revoke(expected_revision,name);
 }
 api::MetadataPage list(const std::string& cursor,std::int64_t limit)const{
  if(limit<1||limit>64||cursor.size()>256)throw api::ServiceError("invalid_request","limit must be 1..64 and cursor at most 256 bytes");
  auto transport=transport_;api::HolderClient<ipc::FrameTransport> client(transport);auto r=client.list(cursor,limit);
  if(r.outcome==api::PageOutcome::Page)detail::require(static_cast<std::int64_t>(r.records.size())<=limit&&r.complete==r.next.empty(),"inconsistent metadata page");
  else detail::require(r.records.empty()&&r.next.empty()&&!r.complete,"inconsistent metadata refusal");
  return r;
 }
 api::AuditPage audit(const std::string& cursor,std::int64_t max_entries)const{
  if(max_entries<1||max_entries>256||cursor.size()>256)throw api::ServiceError("invalid_request","max_entries must be 1..256 and cursor at most 256 bytes");
  auto transport=transport_;api::HolderClient<ipc::FrameTransport> client(transport);auto r=client.audit(cursor,max_entries);
  detail::require(static_cast<std::int64_t>(r.entries.size())<=max_entries,"oversized audit page");return r;
 }
private: ipc::FrameTransport transport_;
};
// Applies a named credential to one request. Only a program the receiving host
// designated as an enforcer receives anything but forbidden.
class Applier {
public:
 explicit Applier(std::string endpoint):transport_(std::move(endpoint),5000,1u<<20){}
 Applier(std::string endpoint,ipc::Deadline deadline):transport_(std::move(endpoint),deadline,1u<<20){}
 Applier with_server_expectation(std::optional<ipc::ServerExpectation> server)const{auto copy=*this;copy.transport_=transport_.with_server_expectation(std::move(server));return copy;}
 Applier with_cancellation(ipc::CancellationToken token)const{auto copy=*this;copy.transport_=transport_.with_cancellation(std::move(token));return copy;}
 api::CheckResult check(const api::Use& usage)const{auto transport=transport_;api::ApplierClient<ipc::FrameTransport> client(transport);return client.check(usage);}
 // Send the headers once and keep them out of every record, log and reply.
 api::ApplyResult apply(const api::Use& usage)const{
  auto transport=transport_;api::ApplierClient<ipc::FrameTransport> client(transport);auto r=client.apply(usage);
  detail::require((r.outcome==api::ApplyOutcome::Applied)==!r.headers.empty(),"inconsistent apply headers");return r;
 }
private: ipc::FrameTransport transport_;
};
}
