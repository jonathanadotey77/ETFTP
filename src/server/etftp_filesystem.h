#ifndef ETFTP_FILESYSTEM_H
#define ETFTP_FILESYSTEM_H

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <cstdlib>
#include <mutex>

namespace ETFTP
{

class FileSystem
{
private:
    class Node
    {
    private:
        enum NodeType
        {
            e_FILE,
            e_FOLDER
        };

    private:
        std::string path;
        NodeType type;

        Node *parent;
        std::unordered_set<Node *> children;

    public:
        Node(const std::string &path, NodeType type);
    };

private:
    static const std::string FILESYSTEM_ROOT;

public:
    class LockGuard
    {
        LockGuard(const std::string &path);

        ~LockGuard();
    };

public:
    FileSystem() {}

    ~FileSystem();

    bool init();

    // void getMutex(const std::string& path)
};

}

#endif