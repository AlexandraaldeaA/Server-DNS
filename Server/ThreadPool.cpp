#include<ThreadPool.h>

ThreadPool::ThreadPool(size_t threads) : stop(false) 
{
    for (size_t i = 0; i < threads; ++i) 
    {
        workers.emplace_back([this]
        {
            while (true) 
            {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex);

                    // asteapta un task sau oprirea serverului
                    condition.wait(lock, [this] { return stop || !tasks.empty(); });

                    if (stop && tasks.empty()) return;  // opreste thread-ul daca stop este activ si nu sunt task-uri

                    task = std::move(tasks.front());
                    tasks.pop();
                }

                if (task) task();  // executa task-ul
            }
        });
    }
}

ThreadPool::~ThreadPool() 
{
    std::unique_lock<std::mutex> lock(queue_mutex);
    stop = true;

    // semnalizeaza toate thread-urile sa iasa din bucla de executie
    condition.notify_all();

    // asteapta ca toate thread-urile sa termine
    for (auto& worker : workers) 
    {
        worker.join();
    }
}

void ThreadPool::enqueue(std::function<void()> task) 
{
    std::unique_lock<std::mutex> lock(queue_mutex);
    tasks.push(std::move(task));

    // semnalizeaza ca un task a fost adaugat
    condition.notify_one();
}
