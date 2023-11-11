using Plots
using JSON
using Buckets

struct PidUsage
    pid::Int
    times::Vector{Float64}
    usage::Vector{Float64}
    # include the total usage to make sorting easy
    total_usage::Float64
end

function plot_usage!(p, usage::PidUsage; kwargs...)
    plot!(p, usage.times, usage.usage, label = "$(usage.pid)", marker = :o, ms = 1, markerstrokewidth = 0 ; kwargs...)
end

# so that sorting works
Base.isless(u1::PidUsage, u2::PidUsage) = u1.total_usage < u2.total_usage

minimum_time(usages::Vector{<:PidUsage}) =
    minimum(i -> minimum(i.times), usages)

function normalize_times!(usages::Vector{<:PidUsage}, t0)
    for usage in usages
        @. usage.times -= t0
    end
end

function rebin(usage::PidUsage, bins)
    Δbins = diff(bins)
    binned = bucket(Simple(), usage.times, usage.usage, times)
    normalized = binned[2:end] ./ Δbins
    PidUsage(usage.pid, bins[2:end], normalized, sum(normalized))
end

rebin(usages::Vector{<:PidUsage}, bins) =
    map(u -> rebin(u, bins), usages)

function sum_binned_usage(usages::Vector{<:PidUsage})
    # check everything is binned first
    lengths = length.(i.times for i in usages)
    @assert all(==(first(lengths)), lengths)

    out = similar(first(usages).usage)
    @. out = 0
    for usage in usages
        @. out += usage.usage
    end
    PidUsage(-1, first(usages).times, out, sum(out))
end

function parse_cpu_data(data; norm = 1e6)
    map(data["pid_usage"]) do usages
        pid = usages["pid"]
        time_series = usages["usage"]

        times::Vector{Float64} = [i["time"] for i in time_series]
        usage::Vector{Float64} = [i["usage"] for i in time_series]

        @. times = times / norm
        @. usage = usage / norm

        PidUsage(pid, times, usage, sum(usage))
    end 
end

function read_data_file(path)
    raw = open(path) do io
        String(read(io))
    end
    json_data = JSON.parse(raw)
    cpu_data = json_data["cpus"]
    parse_cpu_data.(cpu_data)
end

all_cpus = read_data_file("energy-test.json")
# sort by biggest users
sort!.(all_cpus, rev = true)

start_time = minimum(minimum_time.(all_cpus))
normalize_times!.(all_cpus, start_time)


times = collect(range(0, 300, 101))
# use the tuple trick to broadcast
all_binned = rebin.(all_cpus, (times,))

total_usage = sum_binned_usage.(all_binned)

begin
    p1 = plot(legend = :outertopright, ylabel = "Watts", xlabel = "Seconds", title = "CPU 1")
    for u in all_cpus[1][1:10]
        plot_usage!(p1, u)
    end
    plot_usage!(p1, total_usage[1], label = "total", color = :green, marker = :x)
    p1
end

begin
    p2 = plot(legend = :outertopright, ylabel = "Watts", xlabel = "Seconds", title = "CPU 2")
    for u in all_cpus[2][1:10]
        plot_usage!(p2, u)
    end
    plot_usage!(p2, total_usage[2], label = "total", color = :green, marker = :x)
    p2
end

plot(p1, p2, layout = (2, 1), size=(700, 500))